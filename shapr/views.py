from flask.ext.login import login_required, login_user
from flask import render_template
from . import app
from .forms import LoginForm
from .auth_service import auth_by_password

@app.route('/')
@login_required
def index():
    return 'Hello'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = auth_by_password(
                form.username.data, form.password.data)
        if user:
            login_user(user)
            form.redirect('index')
    return render_template('login.html', form=form)

