#!/usr/bin/python
from flask_principal import Principal, identity_loaded, RoleNeed, UserNeed
from web.core.controllers import mod_core
from web.functions import sigterm_handler, database_link
from flask import Flask, redirect, render_template, url_for
from flask_wtf.csrf import CSRFProtect
from logging.handlers import RotatingFileHandler
from web.manager.api import ListUsersAPI, CreateUserAPI, UserAPI, SettingsAPI
from web.version import __version__ as version
from flask_login import LoginManager, current_user, login_required
from web.manager.controllers import mod_manager, User
from web.auth.controllers import mod_auth
from web.database import db
from web.mail import mail
from web.roles import admin_permission
from flask_moment import Moment
from flask_restful import Api
import logging


app = Flask(__name__)
api = Api(app)
csrf = CSRFProtect(app)
app.config.from_object('config')

if app.config['LOG_ENABLE'] is True:
    file_handler = RotatingFileHandler(app.config['LOG'], maxBytes=app.config['LOG_MAX_SIZE_BYTES'], backupCount=3)
    sql_log = logging.getLogger('sqlalchemy')
    sql_log.setLevel(logging.INFO)
    app.logger.setLevel(logging.DEBUG)
    sql_log.addHandler(file_handler)
    app.logger.addHandler(file_handler)
    app.logger.info('Starting application')

app.config['SQLALCHEMY_DATABASE_URI'] = database_link(app.config['DATABASE_TYPE'], app.config['DATABASE_NAME'],
                                                      app.config['DATABASE_HOST'], app.config['DATABASE_USER'],
                                                      app.config['DATABASE_PASSWORD'], app.config['DATABASE_PORT'])

Principal(app)
login_manager = LoginManager(app)
mail.init_app(app)
db.init_app(app)
moment = Moment(app)

app.register_blueprint(mod_manager)
app.register_blueprint(mod_auth)
app.register_blueprint(mod_core)

api.add_resource(ListUsersAPI, '/api/v1/users/list')
api.add_resource(CreateUserAPI, '/api/v1/user/create')
api.add_resource(UserAPI, '/api/v1/user/<string:user_id>')
api.add_resource(SettingsAPI, '/api/v1/settings')

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    if hasattr(current_user, 'role'):
        identity.provides.add(RoleNeed(current_user.role))


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def unauthorized_handler():
    return redirect(url_for("index"))


@app.errorhandler(404)
@login_required
def not_found(error):
    return render_template('error.html', error=error, version=version), 404


@app.before_first_request
def create_db():
    db.create_all()
    if not User.query.filter(User.username == 'admin').first():
        user = User('Pimat',
                    'Web',
                    'admin',
                    'pbkdf2:sha256:50000$QZildwvb$ec2954dfe34d5a540d1aa9b64ce8628ab34b4f8d64a04208f15082a431bc5631',
                    'change@me.com',
                    'admin')
        db.session.add(user)
        db.session.commit()


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("core.dashboard"))
    else:
        return render_template("index.html")
