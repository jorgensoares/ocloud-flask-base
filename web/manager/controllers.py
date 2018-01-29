from web.manager.forms import CreateUserForm, UpdateProfileForm
from web.version import __version__ as version
from flask import request, redirect, render_template, flash, url_for, current_app
from werkzeug.security import generate_password_hash
from web.functions import allowed_file
from web.manager.models import User
from web.database import db
from web.roles import admin_permission
from flask import Blueprint
from flask_login import login_required, current_user
import os

mod_manager = Blueprint('manager', __name__, url_prefix='/manager')


@mod_manager.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        user = User.query.filter(User.id == current_user.id).first_or_404()
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.email_alert = form.email_alerts.data
        user.sms_alert = form.sms_alerts.data
        user.phone = form.phone.data
        db.session.commit()
        flash('Profile Updated successfully', 'success')
        return redirect(url_for("manager.profile"))

    return render_template('manager/profile.html', version=version, form=form)


@mod_manager.route('/profile/picture', methods=['POST'])
@login_required
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part', 'warning')
        return redirect(url_for("manager.profile"))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect(url_for("manager.profile"))
    if file and allowed_file(file.filename):
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], current_user.username + '.png'))

    return redirect(url_for("manager.profile"))


@mod_manager.route("/user/<action>/<user_id>", methods=['GET', 'POST'])
@admin_permission.require()
@login_required
def edit_user(action, user_id):
    form = CreateUserForm()

    if action == 'create' and form.validate_on_submit():
        role = form.role.data
        if role == '':
            role = 'user'

        hashed_password = generate_password_hash(form.password.data)
        user = User(form.first_name.data, form.last_name.data, form.username.data, hashed_password, form.email.data,
                    role)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("manager.users"))

    elif request.method == 'POST' and action == 'delete' and user_id:
        User.query.filter(User.id == user_id).delete()
        db.session.commit()
        return url_for("manager.users")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'warning')

    return render_template('manager/user_create.html', version=version, form=form)


@mod_manager.route("/users", methods=['GET'])
@admin_permission.require()
@login_required
def users():
    return render_template('manager/users.html', users=User.query.order_by(User.id.asc()).all(), version=version)


@mod_manager.route("/logs", methods=['GET'])
@login_required
def logs():
    with open(current_app.config['LOG'], "r") as f:
        app_log = f.read()

    return render_template('manager/logs.html', app_log=app_log, version=version)


@mod_manager.route("/settings", methods=['GET', 'POST'])
@admin_permission.require()
@login_required
def settings():
    settings = dict()
    settings['SERVER_IP'] = current_app.config['SERVER_IP']
    settings['DEBUG'] = current_app.config['DEBUG']
    settings['LOG_ENABLE'] = current_app.config['LOG_ENABLE']
    settings['LOG'] = current_app.config['LOG']
    settings['LOG_MAX_SIZE_BYTES'] = current_app.config['LOG_MAX_SIZE_BYTES']
    settings['UPLOAD_FOLDER'] = current_app.config['UPLOAD_FOLDER']
    settings['WTF_CSRF_ENABLED'] = current_app.config['WTF_CSRF_ENABLED']
    settings['SECRET_KEY'] = current_app.config['SECRET_KEY']
    settings['RECAPTCHA'] = current_app.config['RECAPTCHA']
    settings['RECAPTCHA_PUBLIC_KEY'] = current_app.config['RECAPTCHA_PUBLIC_KEY']
    settings['RECAPTCHA_PRIVATE_KEY'] = current_app.config['RECAPTCHA_PRIVATE_KEY']
    settings['DATABASE_TYPE'] = current_app.config['DATABASE_TYPE']
    settings['DATABASE_NAME'] = current_app.config['DATABASE_NAME']
    settings['DATABASE_USER'] = current_app.config['DATABASE_USER']
    settings['DATABASE_PASSWORD'] = current_app.config['DATABASE_PASSWORD']
    settings['DATABASE_HOST'] = current_app.config['DATABASE_HOST']
    settings['DATABASE_PORT'] = current_app.config['DATABASE_PORT']
    settings['SQLALCHEMY_TRACK_MODIFICATIONS'] = current_app.config['SQLALCHEMY_TRACK_MODIFICATIONS']
    settings['SQLALCHEMY_ECHO'] = current_app.config['SQLALCHEMY_ECHO']
    settings['MAIL'] = current_app.config['MAIL']
    settings['MAIL_SERVER'] = current_app.config['MAIL_SERVER']
    settings['MAIL_PORT'] = current_app.config['MAIL_PORT']
    settings['MAIL_USERNAME'] = current_app.config['MAIL_USERNAME']
    settings['MAIL_PASSWORD'] = current_app.config['MAIL_PASSWORD']
    settings['MAIL_DEFAULT_SENDER'] = current_app.config['MAIL_DEFAULT_SENDER']
    settings['MAIL_USE_TLS'] = current_app.config['MAIL_USE_TLS']
    settings['MAIL_USE_SSL'] = current_app.config['MAIL_USE_SSL']
    settings['LDAP_HOST'] = current_app.config['LDAP_HOST']
    settings['LDAP_BASE_DN'] = current_app.config['LDAP_BASE_DN']
    settings['LDAP_USER_DN'] = current_app.config['LDAP_USER_DN']
    settings['LDAP_GROUP_DN'] = current_app.config['LDAP_GROUP_DN']
    settings['LDAP_USER_RDN_ATTR'] = current_app.config['LDAP_USER_RDN_ATTR']
    settings['LDAP_USER_LOGIN_ATTR'] = current_app.config['LDAP_USER_LOGIN_ATTR']
    settings['LDAP_BIND_USER_DN'] = current_app.config['LDAP_BIND_USER_DN']
    settings['LDAP_BIND_USER_PASSWORD'] = current_app.config['LDAP_BIND_USER_PASSWORD']
    settings['LDAP_PORT'] = current_app.config['LDAP_PORT']
    settings['LDAP_USE_SSL'] = current_app.config['LDAP_USE_SSL']

    return render_template('manager/settings.html',version=version, settings=settings)
