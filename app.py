from flask import Flask, request, jsonify, make_response, Response, json
from flask_sqlalchemy import SQLAlchemy
app = Flask(__name__)

app.config.from_pyfile('config.py')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    reset_token = db.Column(db.String())

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

from views import *

if __name__ == '__main__':
     app.run()