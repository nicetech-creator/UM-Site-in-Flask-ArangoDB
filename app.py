
import sys
import os
import random
import json
import string
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, session, make_response
from flask_bcrypt import Bcrypt         #package for password encryption
from pyArango.connection import *
from oauthlib.oauth2 import WebApplicationClient
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
# end of import libs-----------------------------------------------------------------------------

# ----------------------- Default Setting ------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
bcrypt = Bcrypt(app)
app.secret_key = os.urandom(24)

ADBUSER = os.environ.get('ARANGO_USER', default = 'root')
ADBPASS = os.environ.get('ARANGO_PASS', default = 'notouch')
## -------------------Database initinalize-----------------------------
try:
    conn = Connection(username=ADBUSER, password=ADBPASS)
except:
    print ('Please check your arango servier is running!')
    sys.exit(-1)
try:
    db = conn['project']

except:
    # create database if not existing on ArangoDB server
    db = conn.createDatabase(name='project')
    usersCollection = db.createCollection(name='users')

    # create the admin user
    admin = usersCollection.createDocument() 
    admin['name'] = 'Administrator'
    admin['email'] = 'admin@admin.com'
    admin['password'] = bcrypt.generate_password_hash('password').decode('utf-8')
    admin['role'] = 'admin'
    admin['address'] = 'somewhere'
    admin['state'] = 'active'
    admin['_key'] = admin['email']
    admin['department'] = 'CS'
    admin.save()

    # create default departments
    departments = db.createCollection(name='departments')
    dep = departments.createDocument()
    dep['_key'] = 'CS'
    dep.save()
    dep = departments.createDocument()
    dep['_key'] = 'EE'
    dep.save()

    # create session collection
    sessions = db.createCollection(name='sessions')
## --------------------------End of database Intialize--------------------------    

## -------------------------Google App Settings---------------------------------
GOOGLE_CLIENT_ID = '345836232183-i5rvc58i5bt2usfeq665rdl0t1al8a4r.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'z3fWORWwLr7Xe3wDTtSu7xm8'
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)
## -------------------------End Google App Setting -----------------------------

# ----------------------End Default Setting ------------------------------------




# --------------------------Form Classes for Login, Register -------------------
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    department = StringField('Department',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')    

    def validate_email(form, field):
        if field.data in db['users']:
            raise ValidationError('Thie Email is in use!')

class ProfileForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired()])
    department = StringField('Department',
                           validators=[DataRequired()])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    address = StringField('Address',
                           validators=[Length(min=2, max=20)])
    submit = SubmitField('Save Changes')

class PasswordForm(FlaskForm):
    password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
# -------------------------- End Form Classes for Login, Register --------------



# -------------------------- Routing -------------------------------------------
@app.route('/')
@app.route('/home')
def home():
    logedin = request.cookies.get('sessionID', 'nosession') in db['sessions']
    print ('logged user?', logedin)
    return render_template('home/home.html', logedin=logedin)

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            current_user = db['users'][form.email.data]
            if bcrypt.check_password_hash(current_user['password'], form.password.data):
                # create a new session for current user
                new_session_id = _keyGen()
                session_create({
                    '_key' : new_session_id,
                    'user_name' : current_user['name'],
                    'role' : current_user['role'] == 'admin',
                    'user_email' : current_user['email']
                })
                # set cookie for session key
                response = make_response(redirect('/dashboard'))
                response.set_cookie('sessionID', new_session_id)
                print ('User logged in successfuly')
                return response
        except Exception as e:
            print (e)
            pass
        flash('Wrong Credential!', 'danger')
    return render_template('home/login.html', title='Login', form=form)
# end login()

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # create a new user with CRUD funcs
        r =  user_create({
            'name' : form.username.data,
            'email' : form.email.data,
            'department' : form.department.data,
            'password' : bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            'role' : 'user'
            })
        if r == True:
            if form.department.data not in db['departments']:
                dep_create({
                    'name' : form.department.data
                })
            flash(f'Account created for {form.username.data}!', 'success')
            print ('New user Created')
        else:
            flash('Account Creation Failed!', 'error')
            print('Uesr Creation Failed')
    return render_template('home/register.html', form=form)
# end def register

@app.route('/logout')
def logout():
    session_delete(request.cookies.get('sessionID', 'nosession'))
    return redirect(url_for('home'))
# end def logout

@app.route('/dashboard', methods = ['GET', 'POST'])
def dashboard():
    session_id = request.cookies.get('sessionID', 'nosession')
    if session_id not in db['sessions']:
        return redirect(url_for('login'))

    current_session = db['sessions'][session_id]
    current_user = db['users'][current_session.user_email]

    form =  ProfileForm()
    pass_form = PasswordForm()
    if form.validate_on_submit():
        print ('user update request came')
        # update user info
        user_update(current_user['email'], {
            'name' : form.username.data,
            'address': form.address.data,
            'email' : form.email.data,
            'department' : form.department.data
        })
        session_update(session_id, {
            'user_name' : form.username.data,
            'user_email' : form.email.data
        })
    elif request.method == 'GET':
        form.username.data = current_user.name
        form.email.data = current_user.email
        form.address.data = current_user.address
        form.department.data = current_user.department

    data = {
        'username' : current_session.user_name,
        'admin' : current_session.role,
        'useremail' : current_session.user_email
    }

    
    return render_template('dashboard/dashboard.html', data = data, form = form, pass_form = pass_form)

@app.route('/dashboard/users')
def dashboard_users():
    session_id = request.cookies.get('sessionID', 'nosession')
    if session_id not in db['sessions']:
        return redirect(url_for('login'))
    current_session = db['sessions'][session_id]
    data = {
        'user' : current_session.user,
        'admin' : current_session.role,
        'useremail' : current_session.user_email
    }
    users = user_read()
    return render_template('dashboard/users.html', data = data, users=users)

@app.route('/dashboard/password_change', methods = ['POST'])
def dashboard_password_change():
    form = PasswordForm()
    if form.validate_on_submit():
        current_session = db['sessions'][request.cookies.get('sessionID', 'nosession')]
        current_user = db['users'][current_session['user_email']]
        if bcrypt.check_password_hash(current_user['password'], form.password.data):
            print ('new password', form.new_password.data)
            user_update(current_user['email'], {
                'password' : bcrypt.generate_password_hash(form.new_password.data).decode('utf-8'),
            })

    return redirect(url_for('dashboard'))

@app.route('/dashboard/departments', methods = ['GET', 'POST'])
def dashboard_departments():
    session_id = request.cookies.get('sessionID', 'nosession')
    if session_id not in db['sessions']:
        return redirect(url_for('login'))
    current_session = db['sessions'][session_id]
    data = {
        'user' : current_session.user,
        'admin' : current_session.role,
        'useremail' : current_session.user_email
    }
    if request.method == 'POST':
        name = request.form.get('name', '')
        if name != '':
            dep_create({
                'name' : name
            })

    deps = dep_read()
    return render_template('dashboard/departments.html', data = data, deps=deps)
# -------------------------- End Routing ---------------------------------------



# -------------------------- CRUD Layer ----------------------------------------

## ------------------------- User CRUD -----------------------------------------
def user_create(user_data):
    # if primary key(email) doesn't exists then fail and return false
    if 'email' not in user_data:
        return False
    new_user = db['users'].createDocument()
    for key in user_data:
        new_user[key] = user_data[key]
    new_user['_key'] = new_user['email']
    new_user.save()
    return True
# end user_create

def user_update(old_email, user_data):
    if old_email not in db['users']:
        return False
    user = db['users'][old_email]
    for key in user_data:
        user[key] = user_data[key]
    user['_key'] = user['email']
    user.save()
    return True
# end user_update


def user_read(user_email=None):
    aql = """
            FOR u IN users RETURN u
        """
    result = db.AQLQuery(aql, rawResults = True)
    return result.response['result']
# end user_read

def user_delete(user_email):
    if user_email not in db['users']:
        return False
    db['users'][user_email].delete()
    return True
## ------------------------- End User CRUD -------------------------------------

## ------------------------- Department CRUD -----------------------------------
def dep_create(dep_data):
    # primary key check
    if 'name' not in dep_data:
        return False
    new_dep = db['departments'].createDocument()
    for key in dep_data:
        new_dep[key] = dep_data[key]
    new_dep['_key'] = new_dep['name']
    new_dep.save()
    return True

def dep_read():
    aql = """
            FOR u IN departments RETURN u
        """
    result = db.AQLQuery(aql, rawResults = True)
    return result.response['result']

def dep_delete(key):
    if key not in db['departments']:
        return False
    db['departments'][key].delete()
    return True

def dep_update(_key, dep_data):
    if _key not in db['departments']:
        return False
    dep = db['departments'][_key]
    for key in dep_data:
        dep[key] = dep_data[key]
    dep['_key'] = dep_data['name']
    dep.save()
    return True
## ------------------------- End Department CRUD -------------------------------

## ------------------------- Session CRUD --------------------------------------
def session_create(session_data):
    if '_key' not in session_data:
        return False
    new_session = db['sessions'].createDocument()
    for key in session_data:
        new_session[key] = session_data[key]
    new_session.save()
    return True

def session_update(session_id, session_data):
    if session_id not in db['sessions']:
        return False
    current_session = db['sessions'][session_id]
    for key in session_data:
        current_session[key] = session_data[key]
    current_session.save()
    return True

def session_delete(session_id):
    if session_id in db['sessions']:
        db['sessions'][session_id].delete()

## ------------------------- End Session CRUD ----------------------------------

# -------------------------- End CRUD Layer ------------------------------------



# ------------------------- APIS -----------------------------------------------

## ------------------------USER API---------------------------------------------
@app.route('/api/v1/user', methods = ['GET'])
def api_user_read():
    return jsonify({
            'users' : user_read()
    })
# end def api_user_read() 

@app.route('/api/v1/user', methods = ['POST'])
def api_user_create():
    if user_create(request.form) == True:
        return jsonify({
            'success' : 'User Created Successfuly'
        })
    return jsonify({
            'error' : 'User Creating Failed'
    })
# end def api_user_create()

@app.route('/api/v1/user/<key>', methods = ['DELETE'])
def api_user_delete(key):
    if user_delete(key) == True:
        return jsonify({
            'success' : 'User Deleted Successfuly'
        })
    return jsonify({
        'error' : 'User Deletion Failed'
    })
# end def api_user_delete()

@app.route('/api/v1/user/<key>', methods = ['PUT'])
def api_user_update(key):
    if user_update(key, request.form) == True:
        return jsonify({
            'success' : 'User Info Updated Successfuly'
        })
    return jsonify({
        'error' : 'User Info Update Failed'
    })
# end def api_update
## ------------------------END USER API ----------------------------------------

## ------------------------ Department API -------------------------------------
@app.route('/api/v1/department', methods = ['GET'])
def api_dep_read():
    return jsonify({
            'departments' : dep_read()
    })

@app.route('/api/v1/department/<key>', methods = ['DELETE'])
def api_dep_delete(key):
    if dep_delete(key) == True:
        return jsonify({
            'success' : 'Department Deleted Successfuly'
        })
    return jsonify({
        'error' : 'Department Deletion Failed'
    })

@app.route('/api/v1/department/<key>', methods = ['PUT'])
def api_dep_update(key):
    if dep_update(key, request.form) == True:
        return jsonify({
            'success' : 'Department Updated Successfuly'
        })
    return jsonify({
        'error' : 'Department Update Failed'
    })
## ------------------------ End Department API ---------------------------------

# ------------------------- END APIS -------------------------------------------



# -------------------------- Helper Functions ----------------------------------

## helper funtion to generate random session key
def _keyGen(stringLength = 128):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))
## end def _keyGen

# -------------------------- End Helper Functions ------------------------------



# -------------------------- Main ----------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
# -------------------------- End Main ------------------------------------------