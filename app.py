import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Load environment variables from .env
load_dotenv()

# --- 1. App Setup ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Load the secret key from the environment, with a fallback for development
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_key')
# Configure the database location
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'ctf.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Checks if a filename has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- 2. Database & Login Setup ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
# If a user tries to access a page they need to be logged in for,
# redirect them to the 'login' page.
login_manager.login_view = 'login'

# --- 3. Database Models ---

# The UserMixin is required by Flask-Login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    score = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_name = db.Column(db.String(100), unique=True)
    flag_value = db.Column(db.String(100), unique=True, nullable=False)
    points = db.Column(db.Integer, nullable=False)

class SolvedChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flag_id = db.Column(db.Integer, db.ForeignKey('flag.id'), nullable=False)
    
    # This ensures a user can only solve a flag once
    db.UniqueConstraint('user_id', 'flag_id')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128)) # Storing in plain text for the vulnerability!

# This function is required by Flask-Login to load the current user from session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- 4. Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/submit', methods=['POST'])
@login_required
def submit_flag():
    # 1. Get the flag from the form
    submitted_flag = request.form.get('flag')
    if not submitted_flag:
        flash('You must enter a flag!', 'error')
        return redirect(url_for('index'))

    # 2. Check if this flag even exists in our database
    correct_flag = Flag.query.filter_by(flag_value=submitted_flag).first()
    
    # 3. If flag is incorrect or doesn't exist
    if not correct_flag:
        flash('That flag is incorrect. Try again!', 'error')
        return redirect(url_for('index'))

    # 4. Check if user has ALREADY solved this
    has_solved = SolvedChallenge.query.filter_by(
        user_id=current_user.id, 
        flag_id=correct_flag.id
    ).first()

    if has_solved:
        flash('You have already solved this challenge!', 'info')
        return redirect(url_for('index'))

    # 5. --- SUCCESS! ---
    # Add the points to the user's score
    current_user.score += correct_flag.points
    
    # Mark this challenge as solved for this user
    new_solve = SolvedChallenge(user_id=current_user.id, flag_id=correct_flag.id)
    db.session.add(new_solve)
    
    # Save the changes to the database
    db.session.commit()
    
    flash(f'Correct! You earned {correct_flag.points} points!', 'success')
    return redirect(url_for('index'))

# --- 5. Main App Routes ---

@app.route('/')
def index():
    # This is the main dashboard
    return render_template('index.html')


# --- 6. CTF Challenge Routes (We will add these next) ---
# ... Challenges will go here ...
@app.route('/search')
@login_required
def search():
    # Get the search query from the URL (e.g., /search?q=test)
    query = request.args.get('q', '') # Get 'q' parameter, default to empty string
    
    # --- The HACK is here ---
    # We pass the 'query' variable to the template.
    # The vulnerability will be in the HTML, where we render it unsafely.
    
    # 1. Create the HTML page
    resp = make_response(render_template('search.html', search_query=query))
    
    # 2. Set the secret flag as a cookie, just like before
    resp.set_cookie('flag_cookie', 'flag{R3fl3ct3d_XSS_is_Fast}')
    
    return resp

@app.route('/admin-login', methods=['GET', 'POST'])
@login_required
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # --- THE VULNERABILITY ---
        # This is a classic insecure query. It's building the SQL string
        # by just pasting the user's input into it.
        # A smart user can "break out" of the string.
        
        # DO NOT EVER DO THIS IN A REAL APP!
        query = f"SELECT * FROM admin WHERE username = '{username}' AND password = '{password}'"
        
        # We execute the raw SQL query
        result = db.session.execute(db.text(query)).first()
        
        if result:
            # If the query returned a user, log them in!
            # The SQLi bypass will make this 'result' not None.
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/admin-dashboard')
@login_required # We still require a user to be logged in to the main app
def admin_dashboard():
    # This page just shows the flag
    return render_template('admin_dashboard.html')

@app.route('/robots.txt')
def robots_txt():
    """
    This route simulates a misconfigured robots.txt file,
    which is a common place for recon.
    """
    # This text will be served when the user visits /robots.txt
    robots_content = """
User-agent: *
Disallow: /admin-login
Disallow: /profile/

# Note to dev: We really need to secure our backups.
# Do not allow crawlers to index the /static/server_logs.bak file.
# Disallow: /static/server_logs.bak
"""
    # We return it as plain text
    return Response(robots_content, mimetype='text/plain')

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):

    # --- THE HACK ---
    # We check for the special, "hidden" ID.
    if user_id == 0:
        # If they guess '0', send them to the secret page.
        return render_template('profile_hidden.html')

    # --- Normal Users ---
    # If it's any other ID, just show their normal profile.
    user_to_view = User.query.get(user_id)

    if not user_to_view:
        flash('User not found.', 'error')
        return redirect(url_for('index'))

    return render_template('profile.html', user=user_to_view)

@app.route('/uploader', methods=['GET', 'POST'])
@login_required
def uploader():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        # --- THE NEW VULNERABILITY LOGIC ---
        
        # 1. Check if the file is NOT allowed
        if file and not allowed_file(file.filename):
            # This is the HACK! The user uploaded a non-image file.
            # We "return" the flag by flashing it.
            
            # First, we get the flag from our database
            flag_obj = Flag.query.filter_by(challenge_name='Insecure File Upload').first()
            if flag_obj:
                flash(f'DANGER! Invalid file type. System breach detected! Flag: {flag_obj.flag_value}', 'success')
            else:
                flash('Vulnerability detected, but flag not found in DB.', 'error')
            
            return redirect(url_for('uploader'))
        
        # 2. This is the "normal" path (if they upload a real image)
        if file and allowed_file(file.filename):
            # We securely save it, but this is the "losing" path for the CTF.
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            flash('That was a valid image! The uploader is working... this isn\'t the hack. Try again.', 'info')
            return redirect(url_for('uploader'))

    return render_template('uploader.html')


# --- 7. Run the App ---
if __name__ == '__main__':
    app.run(debug=True)