from flask_mail import Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired
from web import mail
from web.auth.forms import LoginForm, PasswordForgotForm, PasswordResetForm, PasswordChangeForm
from flask_principal import Identity, AnonymousIdentity, identity_changed
from flask import redirect, render_template, flash, url_for, current_app, session
from werkzeug.security import generate_password_hash
from web.functions import get_now
from web.database import db
from flask import Blueprint
from flask_login import login_required, login_user, logout_user
from web.version import __version__ as version

mod_auth = Blueprint('auth', __name__, url_prefix='/auth')


@mod_auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.user
        login_user(user, remember=True)
        user.last_login = get_now()
        user.login_attempts = 0
        db.session.commit()
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
        flash('Welcome {0} {1}'.format(user.first_name, user.last_name), 'success')
        return redirect(url_for("index"))
    else:
        # failed login actions can go here later on
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'warning')

    return render_template("index.html", form=form)


@mod_auth.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    return redirect(url_for("index"))


@mod_auth.route("/password-change", methods=['GET', 'POST'])
@login_required
def password_change():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        user = form.user
        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        if current_app.config['MAIL']:
            message = '''Hello %s,\n\n This is e-mail is to inform you that you have changed your password successfully.
             \nIf this request was not made by you please contact support immediately.\n
             \nThank you.\n Pimat\n\n''' % user.username

            subject = "Pimat Password Change Notice - %s" % user.username
            msg = Message(recipients=[user.email], body=message, subject=subject)
            mail.send(msg)

        flash('Password changed successfully, you should logout and login again!', 'success')
        return redirect(url_for("core.dashboard"))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'warning')

    return render_template('auth/password_change.html', version=version)


@mod_auth.route("/password-forgot", methods=['GET', 'POST'])
def password_forgot():
    form = PasswordForgotForm()
    if form.validate_on_submit():
        user_details = form.user
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=600)
        token = s.dumps({'id': user_details.id})
        message = '''Hello, \n\n To reset your password go to: http://%s/password_reset \n\n Token: \n %s''' % \
                  (current_app.config['SERVER_IP'], token)
        subject = "Pimat Password Reset - %s" % user_details.username
        msg = Message(recipients=[user_details.email], body=message, subject=subject)
        mail.send(msg)
        flash('Please verify you mailbox!', 'success')
        return redirect(url_for("auth.password_reset"))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'warning')

    return render_template('auth/password_forgot.html', version=version, form=form)


@mod_auth.route("/password-reset", methods=['GET', 'POST'])
def password_reset():
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = form.user
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(form.token.data)
        except SignatureExpired:
            flash('Expired Token', 'danger')
            return render_template('auth/password_reset_form.html', version=version, form=form)
        except BadSignature:
            flash('Invalid Token', 'danger')
            return render_template('auth/password_reset_form.html', version=version, form=form)

        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        message = '''Hello %s,\n\n This is e-mail is to inform you that you have reset your password successfully. 
        \nIf this request was not made by you please contact support immediately.\n 
        \nThank you.\n Pimat\n\n''' % user.username

        subject = "Pimat Password Reset Notice - %s" % user.username
        msg = Message(recipients=[user.email], body=message, subject=subject)
        mail.send(msg)
        flash('Password updated successfully, Please login.', 'success')
        return redirect(url_for("login"))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'warning')

    return render_template('auth/password_reset_form.html', version=version, form=form)