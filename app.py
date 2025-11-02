import os
import subprocess
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Load environment variables from .env
load_dotenv()

# ----- 1. App Setup -----
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_fallback_key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'ctf.db')
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Checks if a filename has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ----- 2. Database & Login Setup -----
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'

# --- 3. Database Models ---

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
    
    
    db.UniqueConstraint('user_id', 'flag_id')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128)) 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----- 4. Authentication Routes -----

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
    
    submitted_flag = request.form.get('flag')
    if not submitted_flag:
        flash('You must enter a flag!', 'error')
        return redirect(url_for('index'))

    
    correct_flag = Flag.query.filter_by(flag_value=submitted_flag).first()
    
   
    if not correct_flag:
        flash('That flag is incorrect. Try again!', 'error')
        return redirect(url_for('index'))

    
    has_solved = SolvedChallenge.query.filter_by(
        user_id=current_user.id, 
        flag_id=correct_flag.id
    ).first()

    if has_solved:
        flash('You have already solved this challenge!', 'info')
        return redirect(url_for('index'))

    # 5. ----- SUCCESS! -----
    current_user.score += correct_flag.points
    
    new_solve = SolvedChallenge(user_id=current_user.id, flag_id=correct_flag.id)
    db.session.add(new_solve)
    
    db.session.commit()
    
    flash(f'Correct! You earned {correct_flag.points} points!', 'success')
    return redirect(url_for('index'))

# ----- 5. Main App Routes -----

@app.route('/')
def index():
    
    return render_template('index.html')


# ----- 6. CTF Challenge Routes -----
@app.route('/search')
@login_required
def search():
    
    query = request.args.get('q', '') 

    resp = make_response(render_template('search.html', search_query=query))
    resp.set_cookie('flag_cookie', 'flag{R3fl3ct3d_XSS_is_Fast}')
    
    return resp

@app.route('/admin-login', methods=['GET', 'POST'])
@login_required
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        query = f"SELECT * FROM admin WHERE username = '{username}' AND password = '{password}'"
        

        result = db.session.execute(db.text(query)).first()
        
        if result:
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/admin-dashboard')
@login_required 
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/robots.txt')
def robots_txt():
    """
    This route simulates a misconfigured robots.txt file,
    which is a common place for recon.
    """
    robots_content = """
        User-agent: *
        Disallow: /admin-login
        Disallow: /profile/

        # Note to dev: We really need to secure our backups.
        # Do not allow crawlers to index the /static/server_logs.bak file.
        # Disallow: /static/server_logs.bak
    """
    return Response(robots_content, mimetype='text/plain')

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):

    
    if user_id == 0:
        return render_template('profile_hidden.html')

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

        if file and not allowed_file(file.filename):

            flag_obj = Flag.query.filter_by(challenge_name='Insecure File Upload').first()
            if flag_obj:
                flash(f'DANGER! Invalid file type. System breach detected! Flag: {flag_obj.flag_value}', 'success')
            else:
                flash('Vulnerability detected, but flag not found in DB.', 'error')
            
            return redirect(url_for('uploader'))
        

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            flash('That was a valid image! The uploader is working... this isn\'t the hack. Try again.', 'info')
            return redirect(url_for('uploader'))

    return render_template('uploader.html')

@app.route('/ping', methods=['GET', 'POST'])
@login_required
def ping_tool():
    output = ""

    if request.method == 'POST':
        ip_address = request.form.get('ip_address')

        command = f"ping -n 3 {ip_address}" 

        if ';' in ip_address or '&' in ip_address:
            flag_obj = Flag.query.filter_by(challenge_name='OS Command Injection').first()
            if flag_obj:
                flash(f'Command Injection detected! Here is your reward: {flag_obj.flag_value}', 'success')
            else:
                flash('Vulnerability detected, but flag not found in DB.', 'error')

        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"An error occurred: {e}"

    return render_template('ping_tool.html', command_output=output)

# ----- 7. Run the App -----
if __name__ == '__main__':
    app.run(debug=True)