#Flask and related functions
from flask import Flask, request, jsonify
# For Token Authentication
import jwt
import datetime
from functools import wraps
# Secret variables not pushed to github
import secret_keys

# secret_keys.db_password

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_keys.encrypt_key

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


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"