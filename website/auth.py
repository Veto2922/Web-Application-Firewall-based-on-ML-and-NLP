from flask import Blueprint, render_template, request, flash, redirect, url_for ,abort ,jsonify
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
from .request import Request, DBController
from .classifier import ThreatClassifier
import urllib
from .waf import WAF



auth = Blueprint('auth', __name__ )


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        print('user is ====== ' ,user)
        
        WAF.test()
        # for Admin
        if list(WAF.test().keys())[0] == 'valid':
            if email == 'WAF_Admin1@gmail.com':
                if check_password_hash(user.password, password):
                    flash('You are admin ,will be redirected to the Dashbord.....', category='success')
                    login_user(user, remember=True)
                    return redirect('https://veto.grafana.net/d/fe54402a-0814-4dd1-bdfb-4c7c7d6edd14/waf?orgId=1&refresh=5s')
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')
        else:
            abort(403, description=f"You Are attacker {list(WAF.test().keys())[0]} in {list(WAF.test().values())[0]}")

        #For users
        if list(WAF.test().keys())[0] == 'valid':
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home'))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')
        else:
            abort(403, description=f"You Are attacker {list(WAF.test().keys())[0]} in {list(WAF.test().values())[0]}")

    return render_template("login.html", user=current_user)



@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        WAF.test()
        if list(WAF.test().keys())[0] == 'valid':
            if user:
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif len(first_name) < 2:
                flash('First name must be greater than 1 character.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
            else:
                new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                    password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
        else:
            abort(403, description=f"You Are attacker {list(WAF.test().keys())[0]} in {list(WAF.test().values())[0]}")

    return render_template("sign_up.html", user=current_user)
