from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager, UserMixin, logout_user, login_user, login_required, current_user
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from chat import get_response
from datetime import datetime
import model
import os
from db import db

db = SQLAlchemy()


app = Flask(__name__)
CORS(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(250), nullable = False)
    email = db.Column(db.String(150), unique = True)
    password = db.Column(db.String(150))

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500))
    time = db.Column(db.DateTime, default = datetime.now)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

app.config['SECRET_KEY'] = "vdbjcdgyhjsdghsc"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unichat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DATABASE'] = os.path.join(app.root_path, 'unichat.db')

db.init_app(app)


with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/index", methods = ["GET", "POST"])
@login_required
def index_get():
    user = User.query.get(current_user.id)
    message = request.form.get('message')
    if message:
        new_message = ChatMessage(user_id=current_user.id, message = message)
        db.session.add(new_message)
        db.session.commit()
    user_id = current_user.id
    messages = ChatMessage.query.filter_by(user_id=user_id).all()
    # print(messages)
    return render_template("base.html", user = user, messages = messages)


@app.route("/predict", methods = ["GET", "POST"])
def predict():
    text = request.get_json().get("message")
    response = get_response(text)
    message = {"answer": response}
    return jsonify(message)

@app.route("/")
def welcome_page():
    return render_template("welcome.html")

@app.route("/register",methods = ["GET", "POST"] )
def register():
    if request.method == "POST":
        name = request.form.get("full_name")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email = email).first()
        if email_exists:
            flash("Email is already in use.", category = "error")
        elif password1 != password2:
            flash("Password don't Match", category = "error")
        elif len(name) < 5:
            flash("Username is too Short", category = "error")
        elif len(password1) < 6:
            flash("Password is too Short", category = "error")
        elif len(email) < 4:
            flash("Email is too Short", category = "error")
        else:
            new_user = User(name = name, email = email, password =generate_password_hash (password1, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember = True)
            flash('User Created!', category = "success")
            return redirect(url_for('index_get'))
    return render_template("register.html")

@app.route("/login",methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        name =  request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")

        name = User.query.filter_by(name = name).first()
        user = User.query.filter_by(email = email).first()
        if user and name:
            if check_password_hash(user.password, password):
                flash("Logged in!", category = "success")
                login_user(user, remember = True)
                return redirect(url_for('index_get'))
            else:
                flash("Password is incorrect",category = "error")  
        else:
            flash("Email doesn't exist",category = "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("welcome_page"))

if __name__ == "__main__":
    app.run(debug=True)