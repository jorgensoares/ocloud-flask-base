from flask import render_template, Blueprint
from flask_login import login_required
from web.version import __version__ as version

mod_core = Blueprint('core', __name__, url_prefix='/core')


@mod_core.route("/dashboard")
@login_required
def dashboard():
    return render_template("core/dashboard.html", version=version)
