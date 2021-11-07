from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.sql.functions import user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import input_required, length, ValidationError, Email
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/group_3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'secretly'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Login Authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Holds information about each user
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(20), nullable=False)
    lastName = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    firstName = StringField(validators=[input_required(), length(min=2, max=20)],
                            render_kw={"placeholder": "First Name"})
    lastName = StringField(validators=[input_required(), length(min=2, max=20)],
                           render_kw={"placeholder": "Last Name"})
    email = StringField(validators=[input_required(), Email()],
                        render_kw={"placeholder": "Email Address"})
    password = PasswordField(validators=[input_required(), length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    # Needs error handling-function to validate user-email
    # def validate_username(self, email):
    #     validate_username = User.query.filter_by(email=email.data).first()
    #
    #     if validate_username:
    #         flash("Email Taken. Please use different one.")
    #         return url_for('register')


class LoginForm(FlaskForm):
    email = StringField(validators=[input_required(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[input_required(), length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(firstName=form.firstName.data, lastName=form.lastName.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
