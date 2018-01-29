from flask import g
from flask_httpauth import HTTPBasicAuth
from flask_principal import Permission, RoleNeed
from web.manager.models import User
from config import ADMIN_GROUP

api_auth = HTTPBasicAuth()
admin_permission = Permission(RoleNeed(ADMIN_GROUP))


# API authentication setup
@api_auth.verify_password
def verify_password(username_or_token, password):
    # try to authenticate with username/password
    user = User.query.filter_by(username=username_or_token).first()
    if not user or not user.verify_password(password) or user.role != 'admin':
        return False

    g.user = user
    return True
