from flask import Flask, url_for, current_app, session
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager, login_user, UserMixin, current_user, login_required, logout_user
from flask import render_template_string, redirect
from flask_ldap3_login.forms import LDAPLoginForm
from flask_principal import Principal, identity_loaded, Permission, RoleNeed, UserNeed, identity_changed, Identity, \
    AnonymousIdentity

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['DEBUG'] = True
Principal(app)

app.config['ADMIN_GROUP'] = 'CN=Domain Admins,CN=Users,DC=ocloud,DC=cz'

# Setup LDAP Configuration Variables. Change these to your own settings.
# All configuration directives can be found in the documentation.

# Hostname of your LDAP Server
app.config['LDAP_HOST'] = '10.14.10.15'

# Base DN of your directory
app.config['LDAP_BASE_DN'] = 'DC=ocloud,DC=cz'

# Users DN to be prepended to the Base DN
app.config['LDAP_USER_DN'] = 'CN=Users'

# Groups DN to be prepended to the Base DN
app.config['LDAP_GROUP_DN'] = 'CN=Users'

# The RDN attribute for your user schema on LDAP
app.config['LDAP_USER_RDN_ATTR'] = 'cn'

# The Attribute you want users to authenticate to LDAP with.
app.config['LDAP_USER_LOGIN_ATTR'] = 'cn'

# The Username to bind to LDAP with
app.config['LDAP_BIND_USER_DN'] = 'admin@ocloud.cz'

# The Password to bind to LDAP with
app.config['LDAP_BIND_USER_PASSWORD'] = 'Bx7ikKl1'

# SSL settings
app.config['LDAP_PORT'] = 636
app.config['LDAP_USE_SSL'] = True

login_manager = LoginManager(app)              # Setup a Flask-Login Manager
ldap_manager = LDAP3LoginManager(app)          # Setup a LDAP3 Login Manager.

# Create a dictionary to store the users in when they authenticate
# This example stores users in memory.
users = {}
admin_permission = Permission(RoleNeed(app.config['ADMIN_GROUP']))

# Declare an Object Model for the user, and make it comply with the
# flask-login UserMixin mixin.
class User(UserMixin):
    def __init__(self, dn, username, data, memberships):
        self.dn = dn
        self.username = username
        self.data = data
        self.memberships = memberships

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn


# Declare a User Loader for Flask-Login.
# Simply returns the User if it exists in our 'database', otherwise
# returns None.
@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None


# Declare The User Saver for Flask-Ldap3-Login
# This method is called whenever a LDAPLoginForm() successfully validates.
# Here you have to save the user, and return it so it can be used in the
# login controller.
@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    user = User(dn, username, data, memberships)
    users[dn] = user
    return user


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user
    if hasattr(current_user, 'dn'):
        identity.provides.add(UserNeed(current_user.dn))
    if hasattr(current_user, 'data'):
        for role in current_user.data['memberOf']:
            identity.provides.add(RoleNeed(role))


# Declare some routes for usage to show the authentication process.
@app.route('/')
def home():
    # Redirect users who are not logged in.
    if not current_user or current_user.is_anonymous:
        return redirect(url_for('login'))

    # User is logged in, so show them a page with their cn and dn.
    template = """
    <h1>Welcome: {{ current_user.data.cn }}</h1>
    <h1>Welcome: {{ current_user.data.memberOf }}</h1>
    <h2>{{ current_user.dn }}</h2>
    <h2>{{ current_user.id }}</h2>
    """

    return render_template_string(template)


@app.route('/login', methods=['GET', 'POST'])
def login():
    template = """
    {{ get_flashed_messages() }}
    {{ form.errors }}
    <form method="POST">
        <label>Username{{ form.username() }}</label>
        <label>Password{{ form.password() }}</label>
        {{ form.submit() }}
        {{ form.hidden_tag() }}
    </form>
    """

    # Instantiate a LDAPLoginForm which has a validator to check if the user
    # exists in LDAP.
    form = LDAPLoginForm()

    if form.validate_on_submit():
        # Successfully logged in, We can now access the saved user object
        # via form.user.
        login_user(form.user)  # Tell flask-login to log them in.
        print(current_user.dn)
        print(current_user.data['memberOf'])
        identity_changed.send(current_app._get_current_object(), identity=Identity(current_user.dn))
        return redirect('/')  # Send them home

    return render_template_string(template, form=form)


@app.route("/admin", methods=['GET', 'POST'])
@admin_permission.require()
@login_required
def admin():
    template = """
    <h1>Welcome: {{ current_user.data.cn }}</h1>
    <h1>Memberships: {{ current_user.data.memberOf }}</h1>
    <h2>{{ current_user.dn }}</h2>
    <h2>Admin Role: {{ config.ADMIN_GROUP }}</h2>
    """
    return render_template_string(template)


@app.route("/logout", methods=["GET"])
def logout():
    logout_user()
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    return redirect(url_for("home"))



if __name__ == '__main__':
    app.run()