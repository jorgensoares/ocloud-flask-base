#
# Application configuration
# Changes the variables below
#
# Server settings
SERVER_IP = 'localhost'
LOG_ENABLE = False
LOG = '../ocloud.log'
LOG_MAX_SIZE_BYTES = 100000
UPLOAD_FOLDER = '../static/images'

# Security settings
DEBUG = True
WTF_CSRF_ENABLED = True
SECRET_KEY = 'super secret string'

# Recaptcha settings
RECAPTCHA = False
RECAPTCHA_PUBLIC_KEY = ''
RECAPTCHA_PRIVATE_KEY = ''

# Database settings
DATABASE_TYPE = 'sqlite'
DATABASE_NAME = '../test.sql'
DATABASE_USER = ''
DATABASE_PASSWORD = ''
DATABASE_HOST = ''
DATABASE_PORT = ''
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = False

# Email settings
MAIL = False
MAIL_SERVER = 'mail.ocloud.cz'
MAIL_PORT = 587
MAIL_USERNAME = 'test@ocloud.cz'
MAIL_PASSWORD = 'guessme'
MAIL_DEFAULT_SENDER = 'test@ocloud.cz'
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# Admin role/group
ADMIN_GROUP = 'admin'

# Enabled LDAP authn
LDAP = False

# Hostname of your LDAP Server
LDAP_HOST = 'dc.ocloud.cz'

# Base DN of your directory
LDAP_BASE_DN = 'DC=ocloud,DC=cz'

# Users DN to be prepended to the Base DN
LDAP_USER_DN = 'CN=Users'

# Groups DN to be prepended to the Base DN
LDAP_GROUP_DN = 'CN=Users'

# The RDN attribute for your user schema on LDAP
LDAP_USER_RDN_ATTR = 'cn'

# The Attribute you want users to authenticate to LDAP with.
LDAP_USER_LOGIN_ATTR = 'cn'

# The Username to bind to LDAP with
LDAP_BIND_USER_DN = 'test@ocloud.cz'

# The Password to bind to LDAP with
LDAP_BIND_USER_PASSWORD = ''

#LDAP SSL settings
LDAP_PORT = 636
LDAP_USE_SSL = True