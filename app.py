import os
from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_compress import Compress
from flask_minify import Minify
from datetime import timedelta
from waitress import serve

import admin as admin_mod
from admin import admin_bp, init_admin
import student as student_mod
from student import student_bp, init_student

load_dotenv()

app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_DOMAIN=None
)
app.config["SESSION_COOKIE_NAME"] = "iste_session"

Compress(app)
Minify(app=app, html=True, js=True, cssless=True)

CORS(app,
     origins=[
         "https://iste-ws2k.onrender.com",
         "capacitor://localhost",
         "capacitor://app.local",
         "https://app.local",
         "http://localhost",
         "http://localhost:5000",
         "null"
     ],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

init_admin(app, {
    "host": os.environ["host"],
    "port": os.environ["port"],
    "admin_user": os.environ["admin"],
    "admin_password": os.environ["password"],
    "admin_password_hash": os.environ["admin_password"],
    "db": os.environ["db"],
})
admin_mod.JWT_SECRET_ADMIN = os.environ["admin_jwt_secret"]

init_student(app, {
    "host": os.environ["host"],
    "port": os.environ["port"],
    "student": os.environ["student"],
    "stud_pwd": os.environ["stud_pwd"],
    "db": os.environ["db"],
    "secret_key": os.environ["secret_key"],
    "jwt_secret": os.environ["jwt_secret"],
}, admin_conn_fn=admin_mod.get_admin_conn)

app.register_blueprint(student_bp)
app.register_blueprint(admin_bp)

if __name__ == "__main__":
    serve(app, host="0.0.0.0", threads=64, port=5000)
