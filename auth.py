from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db
import google.generativeai as genai


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('auth.chatbot'))
        elif user:
            flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
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
            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1, method='pbkdf2:sha256'))
            try:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                flash('An error occurred while creating your account. Please try again.', category='error')
                db.session.rollback()  # Rollback in case of an error
    return render_template("sign_up.html", user=current_user)

@auth.route('/users')
def list_users():
    users = User.query.all()
    user_list = [(user.email, user.first_name) for user in users]
    return jsonify(user_list)

@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword1')
        confirm_password = request.form.get('newPassword2')

        if not check_password_hash(current_user.password, current_password):
            flash('Existing password is incorrect. Please try again.', 'error')
            return redirect(url_for('auth.change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match. Please try again.', 'error')
            return redirect(url_for('auth.change_password'))

        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('change_password.html', user=current_user)

@auth.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    if request.method == 'POST':
        data = request.get_json()
        query = data.get('query')

        print("Received query:", data)

        # Configure API
        genai.configure(api_key="AIzaSyDmgTnmZ7UHObOP16lQEt-0jOOAMTBcTbQ")


        # Create the model
        generation_config = {
            "temperature": 1,
            "top_p": 0.95,
            "top_k": 64,
            "max_output_tokens": 8192,
            "response_mime_type": "text/plain",
        }

        model = genai.GenerativeModel(
            model_name="gemini-1.5-pro",
            generation_config=generation_config,
        )

        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(query)

        if response:
            return jsonify({'response': response.text})
        else:
            return jsonify({'error': 'Failed to get a response from the AI model.'}), 500

    return render_template('chat.html', user=current_user)
