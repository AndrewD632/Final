from flask import Flask, render_template, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from sqlalchemy.sql.functions import current_user
from werkzeug.utils import redirect
from wtforms.fields.simple import StringField, TextAreaField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
from scapy.all import sniff, Raw
import threading



app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
#This is what created the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
#This us used to hash the passwords
bcrypt = Bcrypt(app)

#Verifies that the username and password is correct when logging in
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

#Sucpicous alerts append here
suspicious_alerts = []

#Unhashed passwords append here
unhashed_passwords = []


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Allows the username and password of a user to be put into the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', lazy=True)
    #This shows the output in the posts
    def __repr__(self):
        return f"{self.username}"

#Allows the posts made by a user to be put into the database
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(10), nullable=False)
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #This related back to User to show the username in Posts
    user = db.relationship('User', backref='author_posts', lazy=True)
    #This shows the output in posts
    def __repr__(self):
        return f"Post('{self.title}', '{self.post_date}')"


#Forms - basically these classes creates a form output on the pages
#This form is for the chat page
class ChatForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()]) #This means that the user has to put something in the field
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

#This form is for the registration page
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)]) #Username has to be at least 2 characters and goes up to 20
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')]) #has to be equal to password or you cannot submit
    submit = SubmitField('Sign Up')

#This form is for the login page
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')




#Pages/Routes

#Opens up to the home page
@app.route('/')
@app.route('/home')
def home():
    for alert in suspicious_alerts[:]: #If there is something in alert send a flash message
        flash(alert, 'danger')
        suspicious_alerts.remove(alert)
    return render_template('index.html')

#Opens up to the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm() #References the LoginForm
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        unhashed_passwords.append(form.password.data.strip()) #appends the unhashed password to unhashed_passwords
        if user and bcrypt.check_password_hash(user.password, form.password.data): #If username and hashed password match log them in
            login_user(user, remember=form.remember.data)
            flash('Login successful', 'success')
            return redirect(url_for('home'))
        else: #If re-opens the login page
            flash("Login Unsuccessful. Please Check Username and Password", 'danger')
    return render_template('login.html', title='Login', form=form)

#Allows the user to be able to log out
@app.route('/logout')
def logout():
    logout_user() # log
    flash(f"You have been logged out!", 'info') #send message that you have been logged out
    session.pop("user", None)
    session.pop("password", None)
    return redirect(url_for("login"))

#Opens up to chat page
@app.route('/chat', methods=['GET', 'POST']) #This allows the user to post their message using the POST method
@login_required #If user tried to do /chat in url it will redirect them to the login page
def chat():
    form = ChatForm()  #References the ChatForm
    posts = Post.query.all() #Shows all the posts from the database
    if form.validate_on_submit():
        if current_user.is_authenticated: #If user is logged in let them post
            post = Post(title=form.title.data, message=form.message.data, user_id=current_user.id)
            db.session.add(post) #Posts the message
            db.session.commit()
            flash('Your message has been sent!', 'success')
            form.title.data = ''
            form.message.data = ''
        else: #If not logged in flash a message
            flash("You need to be logged in to send a message.", 'danger')
    return render_template('chat.html', title='New Message', form=form, legend='New Message', posts=posts)

#Opens to the register page
@app.route('/register', methods=['GET', 'POST']) #Allows the users username and password to be put into the database using POST method
def register():
    if current_user.is_authenticated:
        return render_template('index.html')
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        unhashed_passwords.append(form.password.data.strip())
        if user: #If username is in the form data for User flash a message and reopen register
            flash("Username already exists. Please choose a different one.", 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8') #Hashes the passwords
        print('Hashed password:', hashed_password)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit() #Adds username and hashed password to the database
        login_user(new_user) #Logs in the user with the username and password given
        flash('Account has been created! You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)




#Sniffer-alerts
def alerts(packet):
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        for password in unhashed_passwords:
            if password.encode() in payload: #If the password in bytes is in the payload append a alert to suspicious_alerts
                suspicious_alerts.append("Warning: Abnormal Packet Detected! Potential password leakage.")


#Sniffer-Runs
def sniffer():
    sniff(iface="\\Device\\NPF_Loopback", prn=alerts, store=False) #sniffs the traffic on the local host

#Runs the sniffer
def start_sniffer():
    sniffer_thread = threading.Thread(target=sniffer, daemon=True)
    sniffer_thread.start()
    print("Sniffer is running")




#Runs the app
if __name__ == "__main__":
    #runs the app and sniffer and updates the app live
    with app.app_context():
        db.create_all()
    start_sniffer()
    app.run(debug=True) #If debug = true then you can make changes and refresh. If not you have to re-run everytime


