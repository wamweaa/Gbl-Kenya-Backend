from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://shop_wnmi_user:zTx5CesC62OirN9q14F2zLB8bdSDObrb@dpg-cv41hj52ng1s73dccsm0-a.oregon-postgres.render.com/shop_wnmi"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

CATEGORIES = [
    "Piano", "Keyboards", "Guitars", "DJ Equipment",
    "PA Equipment", "Drums", "Music Production",
    "Audio & Visual", "Other"
]

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    cart = db.relationship('Cart', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255))
    stock = db.Column(db.Integer, nullable=False, default=0)
    category = db.Column(db.String(50), nullable=False, default="Other")
    sales_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'image_url': self.image_url,
            'stock': self.stock,
            'category': self.category
        }

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

# JWT Helpers
def generate_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=2)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            token = token.split(" ")[1]  # Bearer <token>
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = data
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token', 'details': str(e)}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Auth Routes
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    role = data.get('role', 'user')
    new_user = User(username=data['username'], password=hashed_pw, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = generate_token(user)
        return jsonify({'message': 'Login successful', 'token': token, 'user_id': user.id, 'role': user.role}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

# Product Routes
@app.route('/products', methods=['GET'])
def list_products():
    category = request.args.get('category')
    query = Product.query
    if category:
        query = query.filter_by(category=category)
    products = query.all()
    return jsonify([product.to_dict() for product in products])

@app.route('/products/<int:id>', methods=['GET'])
def get_product_by_id(id):
    product = Product.query.get_or_404(id)
    return jsonify(product.to_dict())

@app.route('/products', methods=['POST'])
@admin_required
def add_product():
    data = request.get_json()
    new_product = Product(**data)
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/products/<int:id>', methods=['PUT', 'DELETE'])
@admin_required
def modify_product(id):
    product = Product.query.get_or_404(id)

    if request.method == 'PUT':
        data = request.get_json()
        for key, value in data.items():
            setattr(product, key, value)
        db.session.commit()
        return jsonify({'message': 'Product updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()
        return jsonify({'message': 'Product deleted successfully'}), 200

# Cart Routes
@app.route('/cart', methods=['POST'])
@token_required
def add_to_cart():
    data = request.get_json()
    user_id = request.user['user_id']
    new_cart_item = Cart(user_id=user_id, product_id=data['product_id'], quantity=data['quantity'])
    db.session.add(new_cart_item)
    db.session.commit()
    return jsonify({'message': 'Item added to cart'}), 201

@app.route('/cart/<int:user_id>', methods=['GET'])
@token_required
def view_cart(user_id):
    if request.user['user_id'] != user_id and request.user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access to this cart'}), 403

    cart_items = Cart.query.filter_by(user_id=user_id).all()

    items_with_details = []
    for item in cart_items:
        product = Product.query.get(item.product_id)
        items_with_details.append({
            'product_id': item.product_id,
            'quantity': item.quantity,
            'product': product.to_dict() if product else None
        })

    return jsonify(items_with_details)
                                                                                                                                                                                                                                                    
@app.route('/cart/<int:user_id>/<int:product_id>', methods=['DELETE'])
@token_required
def remove_from_cart(user_id, product_id):
    if request.user['user_id'] != user_id and request.user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first_or_404()
    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({'message': 'Item removed from cart'}), 200

@app.route('/cart/<int:user_id>/<int:product_id>', methods=['PUT'])
@token_required
def update_cart_item(user_id, product_id):
    if request.user['user_id'] != user_id and request.user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    cart_item = Cart.query.filter_by(user_id=user_id, product_id=product_id).first_or_404()
    cart_item.quantity = data['quantity']
    db.session.commit()
    return jsonify({'message': 'Cart item updated'}), 200

# Admin Seeder
def create_admin_accounts():
    admins = [
        {"username": "admin1", "password": "admin123", "role": "admin"},
        {"username": "admin2", "password": "admin123", "role": "admin"}
    ]
    for admin in admins:
        if not User.query.filter_by(username=admin['username']).first():
            hashed_pw = bcrypt.generate_password_hash(admin['password']).decode('utf-8')
            db.session.add(User(username=admin['username'], password=hashed_pw, role='admin'))
    db.session.commit()

with app.app_context():
    db.create_all()
    create_admin_accounts()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
