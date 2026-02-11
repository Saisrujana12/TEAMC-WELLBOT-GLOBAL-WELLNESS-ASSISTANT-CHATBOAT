from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for
from database import db, User
from auth import bcrypt, hash_password, check_password, generate_token, decode_token
import os
import re

# Correct imports - Ensure report.py exists in the same directory
try:
    from analysis import calculate_bmi, analyze_wellness
    from report import allowed_file, simulate_ocr
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR: {e}")
    # Fallback to prevent crash if modules are missing
    def allowed_file(f): return False
    def simulate_ocr(f): return {}

from ai_engine import get_wellness_response # Import the AI Engine
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key_here' # REPLACE THIS WITH A STRONG SECRET KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wellbot_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth Configuration - USING ENVIRONMENT VARIABLE TO PREVENT GITHUB SECRETS ALERT
app.config['GOOGLE_CLIENT_ID'] = '172414794098-qluainqni5qu6hvb6k31o5ri8hneli3f.apps.googleusercontent.com'
# IMPORTANT: This was causing the GitHub Secret Alert. Now it checks for ENV var first.
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_CLIENT_SECRET_HERE') 

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

# AI Chatbot API
@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')
    
    if not user_message:
        return jsonify({'error': 'Message is required'}), 400
        
    # Get response from AI Engine
    bot_response = get_wellness_response(user_message, context="User is chatting on the dashboard.")
    
    return jsonify({'response': bot_response})

# API for Dashboard Charts (Milestone 2)
@app.route('/api/health-data', methods=['GET'])
def health_data():
    return jsonify({
        "wellness_score": 78,
        "activity": [65, 59, 80, 81, 56, 55, 40], 
        "bmi_history": [22.5, 22.4, 22.6, 22.3, 22.1], 
        "labels_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "labels_months": ["Jan", "Feb", "Mar", "Apr", "May"]
    })

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_authorize():
    try:
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token, nonce=None)
        
        email = user_info.get('email')
        name = user_info.get('name')
        
        if not email:
            return "Error: Could not retrieve email from Google."
            
        user = User.query.filter_by(email=email).first()
        if not user:
            hashed_pw = hash_password("google_oauth_" + email)
            if not name: name = email.split('@')[0]
            
            user = User(name=name, email=email, password=hashed_pw)
            db.session.add(user)
            db.session.commit()
        
        jwt_token = generate_token(user.id, app.config['SECRET_KEY'])
        if isinstance(jwt_token, bytes):
            jwt_token = jwt_token.decode('utf-8')
            
        return redirect(url_for('dashboard', token=jwt_token))
        
    except Exception as e:
        return f"OAuth Error: {e}"

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/symptoms')
def symptoms():
    return render_template('symptoms.html')

@app.route('/analysis', methods=['GET', 'POST'])
def analysis():
    if request.method == 'POST':
        data = request.get_json()
        weight = data.get('weight')
        height = data.get('height')
        
        bmi = calculate_bmi(weight, height)
        status, message = analyze_wellness(bmi)
        
        return jsonify({
            'bmi': bmi,
            'status': status,
            'message': message
        })
    return render_template('analysis.html')

@app.route('/report', methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and allowed_file(file.filename):
            result = simulate_ocr(file.filename)
            return jsonify(result)
        else:
            return jsonify({'error': 'Invalid file type'}), 400

    return render_template('report.html')

# 1. User Registration API
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not 'email' in data or not 'password' in data or not 'name' in data:
        return make_response(jsonify({"message": "Missing required fields"}), 400)

    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, data['email']):
         return make_response(jsonify({"message": "Invalid email format"}), 400)
    
    user = User.query.filter_by(email=data['email']).first()
    if user:
        return make_response(jsonify({"message": "User already exists. Please login."}), 202)
    
    hashed_pw = hash_password(data['password'])
    new_user = User(
        name=data['name'], 
        email=data['email'], 
        password=hashed_pw,
        language=data.get('language', 'English')
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully!"}), 201

# 2. Login API
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(jsonify({"message": "Could not verify"}), 401)
    
    user = User.query.filter_by(email=auth.get('email')).first()
    if not user:
         return make_response(jsonify({"message": "User not found"}), 401)

    if check_password(user.password, auth.get('password')):
        token = generate_token(user.id, app.config['SECRET_KEY'])
        return jsonify({"token": token})
    
    return make_response(jsonify({"message": "Could not verify"}), 401)

# 3. Protected API
@app.route('/user/profile', methods=['GET'])
def get_user_profile():
    token = None
    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1] 
    
    if not token:
        return jsonify({"message": "Token is missing!"}), 401
    
    try:
        data = decode_token(token, app.config['SECRET_KEY'])
        if data == 'Expired':
             return jsonify({"message": "Token expired, please login again"}), 401
        if data == 'Invalid':
             return jsonify({"message": "Invalid token"}), 401
             
        current_user = User.query.filter_by(id=data).first()
        if not current_user:
             return jsonify({"message": "User not found"}), 404

        return jsonify({
            "name": current_user.name,
            "email": current_user.email
        })
        
    except Exception as e:
        return jsonify({"message": "Token is invalid!"}), 401

if __name__ == '__main__':
    app.run(debug=True)
