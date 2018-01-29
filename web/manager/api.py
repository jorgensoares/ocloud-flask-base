from flask import current_app, jsonify
from werkzeug.security import generate_password_hash
from web.database import db
from web.manager.models import User
from flask_restful import Resource, marshal, fields, reqparse
from web.roles import api_auth as auth

user_fields = {
    'id': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'username': fields.String,
    'email': fields.String,
    'role': fields.String,
    'phone': fields.String,
    'email_alert': fields.String,
    'sms_alert': fields.String,
    'last_login': fields.DateTime,
}


class ListUsersAPI(Resource):
    @auth.login_required
    def get(self):
        return {'users': [marshal(user, user_fields) for user in User.query.order_by(User.id.asc()).all()]}, 200


class CreateUserAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('first_name', type=str, required=True, location='json')
        self.reqparse.add_argument('last_name', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('username', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('password', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('email', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('role', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('phone', type=str, required=False, default="", location='json')
        super(UserAPI, self).__init__()

    @auth.login_required
    def post(self):
        args = self.reqparse.parse_args()
        hashed_password = generate_password_hash(args['password'])
        user = User(args['first_name'], args['last_name'], args['username'], hashed_password, args['email'],
                    args['role'], args['phone'])
        db.session.add(user)
        db.session.commit()


class UserAPI(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('first_name', type=str, required=True, location='json')
        self.reqparse.add_argument('last_name', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('username', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('password', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('email', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('role', type=str, required=True, default="", location='json')
        self.reqparse.add_argument('phone', type=str, required=False, default="", location='json')
        self.reqparse.add_argument('email_alert', type=str, required=False, default="no", location='json')
        self.reqparse.add_argument('sms_alert', type=str, required=False, default="no", location='json')
        super(UserAPI, self).__init__()

    @auth.login_required
    def delete(self, user_id):
        User.query.filter(User.id == user_id).delete()
        db.session.commit()
        return jsonify('User {0} deleted.'.format(user_id))

    @auth.login_required
    def put(self, user_id):
        args = self.reqparse.parse_args()
        return jsonify('Not implemented')


class SettingsAPI(Resource):
    @auth.login_required
    def get(self):
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

        return jsonify(settings)
