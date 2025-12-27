import os
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

db = SQLAlchemy(app)
jwt = JWTManager(app)

OWNER_EMAIL = os.environ.get("OWNER_EMAIL")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")

@app.route("/")
def home():
    return {"message": "Nexus backend is live"}

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    hashed_pw = generate_password_hash(data["password"])
    role = "admin" if data["email"] == OWNER_EMAIL else "user"

    user = User(email=data["email"], password=hashed_pw, role=role)
    db.session.add(user)
    db.session.commit()
    return {"message": "Registered successfully"}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not check_password_hash(user.password, data["password"]):
        return {"error": "Invalid credentials"}, 401

    token = create_access_token(identity={"id": user.id, "role": user.role})
    return {"access_token": token}

@app.route("/admin")
@jwt_required()
def admin():
    user = get_jwt_identity()
    if user["role"] != "admin":
        return {"error": "Admins only"}, 403
    return {"message": "Admin dashboard"}

if __name__ == "__main__":
    app.run()
