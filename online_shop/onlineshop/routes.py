from flask import render_template, url_for, flash, redirect
from onlineshop import app, db, bcrypt
from onlineshop.forms import RegistrationForm, LoginForm
from onlineshop.models import User
from flask_login import login_user, current_user, logout_user

@app.route("/")
@app.route("/home")
def home():
	return render_template('home.html')

@app.route("/basket")
def basket():
	return render_template('basket.html', title='basket')

@app.route("/register", methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash(f'Your Account has been created. You can now log in!', 'success')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)

@app.route("/login",  methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			return redirect(url_for('home'))
		else:
			flash('Login Unsuccesful. Please Check email and password', 'danger')
	return render_template('login.html', title='login', form=form)

@app.route("/logout")
def logout():
	logout_user()
	return redirect(url_for('home'))

@app.route('/nikes')
def trainers():
	return render_template('nikes.html')

@app.route('/jacket')
def jacket():
	return render_template('jacket.html')

@app.route('/hat')
def hat():
	return render_template('hat.html')

@app.route('/jeans')
def jeans():
	return render_template('jeans.html')

@app.route('/tshirt')
def tshirt():
	return render_template('tshirt.html')

@app.route('/checkout')
def payment():
	return render_template('checkout.html')

@app.route('/thankyou')
def cheers():
	flash(f'ORDER SUCCESSFUL')
	return render_template('thankyou.html')
