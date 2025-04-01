#Flask and related functions
from flask import Flask, request, jsonify, session
# For Token Authentication
import jwt as jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import re
# Secret variables not pushed to github
import secret_keys

# secret_keys.db_password

app = Flask(__name__)
# Session configuration
app.config['SECRET_KEY'] = secret_keys.encrypt_key
app.config['SESSION_COOKIE_NAME'] = 'inventory_management_session'  # Name of session cookie
app.config['SESSION_PERMANENT'] = False  # Session will not be permanent
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to session cookie
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production for HTTPS security

users = {}  # Dictionary to store user credentials (username: password)
admins = { "bingbong":"password!23" } # Dictionary to store admin credentials (username: password)
inventory = {}

# Helper function to determine if token is valid
def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("inventory-access-token") # Retrieve token from http header

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

    if username in admins:
        return jsonify({"message" : "User already exists"}), 400

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
        session['user'] = username # Store user in session
        response = jsonify({'message': 'Login successful'})
        
        response.set_cookie('username', username, httponly=True, max_age = 1800) # Set cookie with username
        
        # Set the admin access token
        token = jwt.encode({'username': username, 'exp': datetime.now(timezone.utc) + timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')
        response.set_cookie('inventory-access-token', token)
        return response, 200
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
    response.set_cookie('inventory-access-token', '', expires=0) # clear admin credentials when logging out
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
    return jsonify({'message': f'Hello, {current_user}! Welcome to the Admin inventory management system.'})

@app.route('/user', methods=['GET'])
def user():
    # The current_user is passed after token verification
    return jsonify({'message': f'Hello! Welcome to the inventory management system.'})

# Helper function to generate unique item IDs for each user's inventory
def generate_item_id(username):
    if username not in inventory:
        inventory[username] = {} # Initialize user's inventory
    # Find the next available ID (starting from 1)
    item_ids = inventory[username].keys()
    return max(item_ids, default=0) + 1

# Route to create (POST) inventory item (user)
@app.route('/items', methods=['POST'])
def create_items():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please login.'}), 401
    
    username = session['user']
    
    # Validate required fields in JSON request
    required_fields = ['name', 'description', 'quantity', 'price', 'department', 'location']
    if not request.json or not all(key in request.json for key in required_fields):
        return jsonify({'error:': 'Missing required fields'}), 400
    
    # Extract the item data 
    item_data = {
        'name': request.json['name'],
        'description': request.json['description'],
        'quantity': request.json['quantity'],
        'price': request.json['price'],
        'department': request.json['department'],
        'location': request.json['location'],
    }
    
    # Validate the quantity and price
    if not isinstance(item_data['quantity'], int) or item_data['quantity'] < 0:
        return jsonify({'error': 'Quantity must be a non-negative integer'}), 400
    if not isinstance(item_data['price'], (int, float)) or item_data['price'] < 0:
        return jsonify({'error': 'Price must be a non-negative number'}), 400
    
    # Check if item already exist in user's inventory
    user_inventory = inventory.get(username, {})
    for existing_item_id, existing_item in user_inventory.items():
        if existing_item['name'] == item_data['name']:
            return jsonify({'error': f"Item '{item_data['name']}' already exists in your inventory", 'item_id': existing_item_id}), 409
    
    # Generate item ID and store the item
    # If the item is not exist -> Add new item to inventory
    item_id = generate_item_id(username)
    if username not in inventory:
        inventory[username] = {}
    inventory[username][item_id] = item_data
    
    return jsonify({'message': 'Item created successfully', 'item_id': item_id}), 201

# Route to read (GET) all inventory items
@app.route("/items", methods=["GET"])
def get_items():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in.'}), 401
    
    username = session['user']
    user_inventory = inventory.get(username, {})
    return jsonify(user_inventory), 200

# Route to read (GET) single inventory item by ID (user)
@app.route("/items/<int:item_id>", methods=["GET"])
def get_item(item_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in.'}), 401
    
    username = session['user']
    user_inventory = inventory.get(username, {})
    item = user_inventory.get(item_id)
    if not item:
        return jsonify({'error': 'Item not found'}), 404
    
    return jsonify({item_id: item}), 200

# Route to update (PUT) inventory item by ID (user)
@app.route("/items/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please login.'}), 401
    
    username = session['user']
    user_inventory = inventory.get(username, {})
    if item_id not in user_inventory:
        return jsonify({'error': 'Item not found'}), 404
    
    if not request.json:
        return jsonify({'error': 'No data provided'}), 400
    
    # Update supermarket fields with new data or keep existing data
    item = user_inventory[item_id]
    new_name = request.json.get('name', item['name'])
    item['name'] = new_name
    item['description'] = request.json.get('description', item['description'])
    item['quantity'] = request.json.get('quantity', item['quantity'])
    item['price'] = request.json.get('price', item['price'])
    item['department'] = request.json.get('department', item['department'])
    item['location'] = request.json.get('location', item['location'])
    
    # Validate updated quantity and price
    if not isinstance(item['quantity'], int) or item['quantity'] < 0:
        return jsonify({'error': 'Quantity must be a non-negative integer'}), 400
    if not isinstance(item['price'], (int, float)) or item['price'] < 0:
        return jsonify({'error': 'Price must be a non-negative number'}), 400
    
    # Check for duplicate names after update item
    for existing_item_id, existing_item in user_inventory.items():
        if existing_item_id != item_id and existing_item['name'] == new_name:
            return jsonify({'error': f"Item '{new_name}' already exists in your inventory", 'item_id': existing_item_id}), 409
    
    return jsonify({'message': 'Item updated successfully'}), 200

# Route to delete inventory item by ID (user)
@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in.'}), 401
    
    username = session['user']
    user_inventory = inventory.get(username, {})
    if item_id not in user_inventory:
        return jsonify({'error': 'Item not found'}), 404
    
    del user_inventory[item_id]
    return jsonify({'message': 'Item deleted successfully'}), 200