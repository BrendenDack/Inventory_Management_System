from flask import Flask
import secret_keys

# secret_keys.db_password

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"