from flask import Flask, render_template, render_template_string, flash, url_for, redirect, session, jsonify, request
from flask_wtf import FlaskForm 
from flask_bootstrap import Bootstrap
from wtforms import StringField, BooleanField, HiddenField, validators, Form, PasswordField
from wtforms.validators import InputRequired, Email, Length
from passlib.hash import sha256_crypt
from MySQLdb import escape_string as thwart
from dbconnect import connection
import gc
import requests
from functools import wraps



app = Flask(__name__)

app.secret_key = "This is like super secret. So secret that a TS clearance is needed."

@app.route('/')
@app.route('/home/')
def home():
    try:
        return render_template("html/index.html")
    except Exception as e:
        return(str(e))

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=20)])
    first_name = StringField('First Name', [validators.Length(min=4, max=20)])
    last_name = StringField('Last Name', [validators.Length(min=4, max=20)])
    email = StringField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('login'))

    return wrap

@app.route("/logout/")
@login_required
def logout():
    session.clear()
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for('home'))

@app.route('/login/', methods=["GET","POST"])
def login():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":

            data = c.execute("SELECT * FROM users2 WHERE username = (%s)",
                             (thwart(request.form['username']),))
            
            data = c.fetchone()[2]

            if sha256_crypt.verify(request.form['password'], data):
                session['logged_in'] = True
                session['username'] = request.form['username']

                flash("You are now logged in")
                return redirect(url_for('userInfo'))
                

            else:
                error = "Invalid credentials, try again."

        gc.collect()

        return render_template("html/Login.html", error=error)

    except Exception as e:
        #flash(e)
        error = "This is bad."
        return render_template("html/Login.html", error = error)  


@app.route('/userInfo/')
def userInfo():
    c, conn = connection()
    data2 = c.execute("SELECT * FROM users2 WHERE username = (%s)",
                             (thwart(session['username']),))

    data2 = c.fetchall()
    lst = []

    
    first =  data2[0][3]
    last = data2[0][4]
    email = data2[0][5]

    lst.append(first)
    lst.append(last)
    lst.append(email)
                
    return render_template("html/userInfo.html", lst = lst)
    
@app.route('/sign-up/', methods=["GET","POST"])
def signup():
    try:
        form = RegistrationForm(request.form)

        if request.method == "POST":
            username  = request.form['username']
            first_name = request.form['firstname']
            last_name = request.form['lastname']
            email = request.form['email']
            pass1 = request.form['password']
            pass2 = request.form['password2']

            password = sha256_crypt.encrypt((str(pass1)))
            
            c, conn = connection()

            x = c.execute("SELECT * FROM users2 WHERE username = (%s)",
                          [thwart(username),])

            if int(x) > 0:
                flash("That username is already taken, please choose another")
                return render_template('html/signup.html')

            else:
                c.execute("INSERT INTO users2 (username, password, first_name, last_name, email) VALUES (%s, %s, %s, %s, %s)",
                          [thwart(username), thwart(password), thwart(first_name),thwart(last_name),thwart(email),])
                
                conn.commit()
                flash("Thanks for registering!")
                c.close()
                conn.close()
                gc.collect()

                session['logged_in'] = True
                session['username'] = username

                return redirect(url_for('home'))

        return render_template("html/signup.html")

    except Exception as e:
        return(str(e))

if __name__ == '__main__':
  app.run()
