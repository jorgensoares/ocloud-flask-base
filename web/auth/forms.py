from flask_login import current_user
from flask_wtf import FlaskForm, RecaptchaField, validators
from werkzeug.security import check_password_hash
from wtforms import StringField, PasswordField, validators
from wtforms.validators import DataRequired
from config import RECAPTCHA
from web.manager.models import User


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=self.username.data).first()
        if user is None:
            self.username.errors.append('User not found!')
            return False
        if not user.verify_password(self.password.data):
        #if not check_password_hash(user.password, self.password.data):
            self.password.errors.append('Invalid password!')
            return False

        self.user = user
        return True


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('current_password', validators=[DataRequired()])
    new_password = PasswordField('new_password', [
        validators.DataRequired(),
        validators.EqualTo('verify_new_password', message='Passwords must match')
    ])

    verify_new_password = PasswordField('verify_new_password', validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=current_user.username).first()

        if user is None:
            self.current_password.errors.append('Unknown user')
            return False
        print(self.current_password)
        print(self.new_password)
        if self.current_password.data == self.new_password:
            self.current_password.errors.append('New password must be different then old one!')
            return False

        if not check_password_hash(user.password, self.current_password.data):
            self.current_password.errors.append('Invalid current password!')
            return False

        self.user = user
        return True


class PasswordForgotForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])

    if RECAPTCHA is True:
        recaptcha = RecaptchaField('recaptcha')

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=self.username.data).first()
        if user is None:
            self.username.errors.append('Unknown username')
            return False

        self.user = user
        return True


class PasswordResetForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    new_password = PasswordField('new_password', [
        validators.DataRequired(),
        validators.EqualTo('verify_new_password', message='Passwords must match')
    ])
    verify_new_password = PasswordField('verify_new_password')
    token = StringField('token', validators=[DataRequired()])

    if RECAPTCHA is True:
        recaptcha = RecaptchaField('recaptcha')

    def __init__(self, *args, **kwargs):
        FlaskForm.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = FlaskForm.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(
            username=self.username.data).first()
        if user is None:
            self.username.errors.append('Unknown username')
            return False

        self.user = user
        return True
