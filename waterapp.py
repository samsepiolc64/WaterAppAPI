import os #.env
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime #exp
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:pg@localhost/waterapp'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


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
            return jsonify({'message':'token wygasl'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'bledny token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message':'nie mozna wykonac tej funkcji'})
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users':output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'nie mozna wykonac tej funkcji'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'nie znaleziono uzytkownika'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user':user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'nie mozna wykonac tej funkcji'})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'nowy uzytkownik zostal utworzony'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'nie mozna wykonac tej funkcji'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'nie znaleziono uzytkownika'})
    user.admin = True
    db.session.commit()
    return jsonify({'message' : 'uzytkownik uzyskal prawa admina'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'nie mozna wykonac tej funkcji'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'nie znaleziono uzytkownika'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'uzytkownik zostal usuniety'})
#add jwt
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate':'Basic realm="wymagany login"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate':'Basic realm="wymagany login"'})
    #tworzenie tokena
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-8')})
    return make_response('nie mozna zweryfikowac', 401, {'WWW-Authenticate': 'Basic realm="wymagany login"'})

if __name__ == '__main__':
     app.run(debug=True)
