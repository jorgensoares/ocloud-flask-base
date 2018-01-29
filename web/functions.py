from datetime import datetime, timedelta
import sys

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


def get_now():
    # get the current date and time as a string
    return datetime.utcnow()


def sigterm_handler(_signo, _stack_frame):
    # When sysvinit sends the TERM signal, cleanup before exiting.
    print("received signal {}, exiting...".format(_signo))
    sys.exit(0)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def database_link(db_type, database, host=None, user=None, password=None, port=None):
    if db_type == 'sqlite':
        return db_type + ':///' + database
    elif db_type == 'mysql':
        if port:
            return db_type + '://' + user + ':' + password + '@' + host + ':' + port + '/' + database
        else:
            return db_type + '://' + user + ':' + password + '@' + host + '/' + database
    elif db_type == 'postgresql':
        if port:
            return db_type + '://' + user + ':' + password + '@' + host + ':' + port + '/' + database
        else:
            return db_type + '://' + user + ':' + password + '@' + host + '/' + database
    else:
        return None
