#Flask and related functions
from flask import Flask, request, jsonify, session
# For Token Authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
import re
# Secret variables not pushed to github
import secret_keys

# secret_keys.db_password

app = Flask(__name__)
# Session configuration
app.config['SECRET_KEY'] = secret_keys.encrypt_key
app.config['SESSION_COOKIE_NAME'] = 'inventory_management_system'  # Name of session cookie
app.config['SESSION_PERMANENT'] = False  # Session will not be permanent
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to session cookie
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production for HTTPS security

users = {}  # Dictionary to store user credentials (username: password)
admins = { "bingbong":"password123" } # Dictionary to store admin credentials (username: password)

# Helper function to determine if token is valid
def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("inventory-access-token") # Retrieve token from http header

        if not token:
            return jsonify({"message" : "Missing Token"}), 401 # Unauthorized because no token
        
        try:
            # Decode given token using the secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username'] # Extract user info
        except:
            return jsonify({'message' : "Invalid Token"}), 401 # Unauthorized because bad token
        
        return f(current_user, *args, **kwargs)
    
    return decorated

#TODO: Finish User Authentication using cookies and sessions

@app.route("/register", methods=["POST"])
def register():
    if not request.json or not 'username' in request.json or not 'password' in request.json:
        return jsonify({"message" : "Missing username or password"}), 400
    
    username = request.json['username']
    password = request.json['password']

    if username in users:
        return jsonify({"message" : "User already exists"}), 400
    
    if len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({"message" : "Password must be at least 8 characters long and contain at least one special character"}), 400
    
    # Store user credentials in the dictionary
    users[username] = password
    return jsonify({"message" : "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = request.json['username']
    password = request.json['password']

    if admins.get(username) == password: # Check if user is admin
        token = jwt.encode({'username': username, 'exp': datetime.now(datetime.timezone.utc) + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    elif users.get(username) != password: # Check if user is in the users dictionary
        return jsonify({'error': 'Invalid username or password'}), 401
    
    session['user'] = username # Store user in session
    response = jsonify({'message': 'Login successful'})
    response.set_cookie('username', username, httponly=True, max_age = 1800) # Set cookie with username
    return response, 200


@app.route("/logout", methods=["POST"])
def logout():
    session.pop('user', None)
    response = jsonify({'message': 'Logout successful'})
    response.set_cookie('username', '', expires=0) # clear cookie
    return response, 200

# Middleware to protect routes, allowing only logged-in users
@app.before_request
def require_login():
    allowed_routes = ['login', 'register']  # Routes that don't require authentication
    if request.endpoint not in allowed_routes and 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in to view this resource.'}), 401

# Protected route (requires valid JWT token)
# Template for creating CRUD routes with JWT authentication Protection
@app.route('/admin', methods=['GET'])
@require_token
def protected_route(current_user):
    # The current_user is passed after token verification
    return jsonify({'message': f'Hello, {current_user}! Welcome to the inventory management system.'})