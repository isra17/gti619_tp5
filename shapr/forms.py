from urllib.parse import urlparse, urljoin
from flask_wtf import Form
from flask import request, url_for, redirect
from wtforms import StringField, PasswordField, HiddenField, SelectField
from wtforms.validators import DataRequired, Optional
from . import User

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def get_redirect_target():
    target = request.args.get('next')
    if is_safe_url(target):
        return target

class RedirectForm(Form):
    next = HiddenField()

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        if not self.next.data:
            self.next.data = get_redirect_target() or ''

    def redirect(self, endpoint='index', **values):
        if is_safe_url(self.next.data):
            return redirect(self.next.data)
        target = get_redirect_target()
        return redirect(target or url_for(endpoint, **values))

class LoginForm(RedirectForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])

class UserForm(Form):
    id = HiddenField()
    username = StringField('username', validators=[])
    password = PasswordField('password', validators=[])
    permissions = SelectField('permissions', choices=[
            (User.PERM_ADMIN, 'Admin'),
            (User.PERM_SQUARE, 'Square'),
            (User.PERM_CIRCLE, 'Circle'),
        ], coerce=int)

