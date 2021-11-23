from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    #if request.method == 'POST':
        #email = request.form.get('email')
        #password = request.form.get('password')
    if request.method == 'GET':
        email = str(request.args.get('email'))
        password = str(request.args.get('password'))

        user = User.query.filter_by(email=email).first()
        if user:
            if user.password == password:
                flash('Sesion inciada', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else :
                flash('Contrasena incorrecta', category='error')
        else:
            flash('Correo incorrecta', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sing_up():
    #if request.method == 'POST':
        #email = request.form.get('email')
        #firstName = request.form.get('firstName')
        #password1 = request.form.get('password1')
        #password2 = request.form.get('password2')
    if request.method == 'GET':
        email = str(request.args.get('email'))
        first_name = str(request.args.get('firstName'))
        password1 = str(request.args.get('password1'))
        password2 = str(request.args.get('password2'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('El correo ya exite', category='error')
        elif len(email) < 4:
            flash('El email debe ser mayor a 4 caracteres.', category ='error')
        elif len(first_name) < 2:
            flash('Nombre debe ser mayor a 1 caracteres.', category ='error')
        elif password1 != password2:
            flash('La contrasena no coincide', category ='error')
        elif len(password2) < 7:
            flash('La contrasena debe ser al menos de 7 caracteres', category ='error')
        else:
            new_user = User(email=email, first_name=first_name, password=password1)
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Cuenta Creada', category ='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)