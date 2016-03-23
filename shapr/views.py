from flask.ext.login import login_required, login_user, current_user, logout_user
from flask import render_template, url_for, redirect
from . import app
from .forms import LoginForm
from .auth_service import auth_by_password

@app.route('/')
@login_required
def index():
    return 'Hello ' + current_user.username

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = auth_by_password(form.username.data, form.password.data)
        if user:
            login_user(user)
            return form.redirect('index')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
