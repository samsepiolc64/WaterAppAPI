import sys
sys.path.append(".")

import re
from flask import request, jsonify, make_response, Response, json
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_sqlalchemy import SQLAlchemy
import datetime #exp
from functools import wraps
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer #password reset

from app import app

db = SQLAlchemy(app)


def getJSON(jsonFile):
    with open(jsonFile, 'r') as jf:
        return json.load(jf)

json_messages = getJSON('./json/messages.json')


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

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : json_messages.get("token_expired", "")}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : json_messages.get("token_incorrect", "")}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def check_login(email, password):
    regex = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    if (not re.search(regex, email)) or (len(password) < 6):
        return True

#*****************************

class JsonResponse(Response):
    def __init__(self, json_dict, status=200):
        super().__init__(response=json.dumps(json_dict), status=status, mimetype="application/json")
@app.route('/add', methods=['POST'])
def add():
    json = request.json
    resp = JsonResponse(json_dict={"answer": json['key']*2}, status=200)
    return resp

#*****************************

@app.route('/admin', methods=['POST'])
def create_admin():
    data = request.get_json()
    if check_login(data['email'], data['password']):
        return jsonify({'message': json_messages.get("login_password_incorrect","")})
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), email=data['email'], password=hashed_password, admin=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : json_messages.get("admin_create", "")})

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message' : json_messages.get("function_not_perform", "")})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : json_messages.get("function_not_perform", "")})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : json_messages.get("user_not_found", "")})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user':user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : json_messages.get("function_not_perform", "")})
    data = request.get_json()
    if check_login(data['email'], data['password']):
        return jsonify({'message': json_messages.get("login_password_incorrect","")})
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : json_messages.get("user_create","")})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : json_messages.get("function_not_perform","")})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : json_messages.get("user_not_found","")})
    user.admin = True
    db.session.commit()
    return jsonify({'message' : json_messages.get("user_promote","")})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : json_messages.get("function_not_perform","")})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : json_messages.get("user_not_found","")})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : json_messages.get("user_delete","")})
#add jwt
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate':'Basic realm="wymagany login"'})
    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate':'Basic realm="wymagany login"'})
    #tworzenie tokena
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})
    return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate': 'Basic realm="wymagany login"'})

#todo
@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    output = []
    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)
    return jsonify({'todos':output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : json_messages.get("todo_not_found","")})
    todo_data = {}
    todo_data['id'] = todo.id
    todo_data['text'] = todo.text
    todo_data['complete'] = todo.complete
    return jsonify(todo_data)

@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message' : json_messages.get("todo_create","")})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : json_messages.get("todo_not_found","")})
    todo.complete = True
    db.session.commit()
    return jsonify({'message' : json_messages.get("todo_complete","")})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({'message' : json_messages.get("todo_not_found","")})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message' : json_messages.get("todo_delete","")})

@app.route('/reset/<public_id>', methods=['GET'])
def get_reset_token(public_id, expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'], expires_sec)
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : json_messages.get("user_not_found","")})
    user.reset_token = s.dumps({'public_id': public_id}).decode('utf-8')
    db.session.commit()
    return jsonify(user.reset_token)

@app.route('/reset/<reset_token>', methods=['PUT'])
def change_password(reset_token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        public_id = s.loads(reset_token)['public_id']
    except:
        return jsonify({'message' : json_messages.get("resettoken_incorrect","")})
    data = request.get_json()
    user = User.query.filter_by(public_id=public_id).first()
    if len(data['new_password']) < 6:
        return jsonify({'message' : json_messages.get("password_change_error","")})
    new_hashed_password = generate_password_hash(data['new_password'], method='sha256')
    user.password = new_hashed_password
    db.session.commit()
    return jsonify({'message' : json_messages.get("password_change","")})
