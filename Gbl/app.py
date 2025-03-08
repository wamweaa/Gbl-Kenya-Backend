from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import send_from_directory
from flask_migrate import Migrate

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_folder="frontend/build", static_url_path="/")
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://neondb_owner:npg_CmQ1eKcfbi7P@ep-bold-shape-a8sgvun3-pooler.eastus2.azure.neon.tech/neondb?sslmode=require"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

CATEGORIES = [
    {
        "name": "Speakers",
        "subcategories": [
            "Bass Speakers",
            "Mid Bass Speakers",
            "Neodymium Speakers",
            "Mid Speakers"
        ]
    },
    {
        "name": "Amplifiers",
        "subcategories": []
    },
    {
        "name": "Mixers",
        "subcategories": [
            "Plain Mixers",
            "Powered Mixers"
        ]
    },
    {
        "name": "Microphones",
        "subcategories": [
            "Wired Microphones",
            "Wireless Microphones"
        ]
    },
    {
        "name": "Tweeters",
        "subcategories": [
            "Tweeter Drivers",
            "Bullet Tweeter Drivers",
            "Neodymium Tweeter Drivers"
        ]
    },
    {
        "name": "Crossover",
        "subcategories": []
    },
    {
        "name": "Stands",
        "subcategories": [
            "Microphone Stands",
            "Speaker Stands"
        ]
    },
    {
        "name": "Guitars",
        "subcategories": [
            "Electric Guitars (Bass, Solo, Rhythm)",
            "Semi-Acoustic Guitars",
            "Box Guitars",
            "Guitar Effects & Pedals"
        ]
    },
    {
        "name": "Spares and Accessories",
        "subcategories": [
            "Microphone Accessories",
            "Capacitors",
            "Battery",
            "Screws and Screwdrivers",
            "Adaptors and Cables",
            "Tweeter Coils",
            "Speaker Spares (Diaphragms)",
            "Caps and Spiders",
            "General Accessories",
            "Multi Meter",
            "Connectors",
            "Fans",
            "Converters",
            "Others"
        ]
    },
    {
        "name": "Saxophones",
        "subcategories": [
            "Alto Saxophones - Silver (46k)",
            "Alto Saxophones - Gold (42k)",
            "Tenor Saxophones (49k)"
        ]
    },
    {
        "name": "Keyboards",
        "subcategories": [
            "Keyboard Models",
            "Sustain Pedal"
        ]
    },
    {
        "name": "Drum Sets and Drum Accessories",
        "subcategories": []
    },
    {
        "name": "Speaker Cabinets",
        "subcategories": [
            "Midrange Cabinets",
            "Full Range Cabinets",
            "Bass Cabinets"
        ]
    },
    {
        "name": "Signal Processors",
        "subcategories": [
            "Equalizers",
            "Crossovers"
        ]
    }
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
    subcategory = db.Column(db.String(50), nullable=True)  # New field

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'image_url': self.image_url,
            'stock': self.stock,
            'category': self.category,
            'subcategory': self.subcategory
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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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


@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

# Catch-all for all other routes and serve index.html
@app.route('/<path:path>')
def catch_all(path):
    return send_from_directory(app.static_folder, 'index.html')
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
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    stock = request.form.get('stock')
    category = request.form.get('category', 'Other')
    subcategory = request.form.get('subcategory')

    image_url = None

    # Handle file upload
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_url = f"/uploads/{filename}"

    # Create and save product
    new_product = Product(
        name=name,
        description=description,
        price=float(price),
        stock=int(stock),
        category=category,
        subcategory=subcategory,
        image_url=image_url  # Save image URL
    )
    
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
        try:
            db.session.delete(product)
            db.session.commit()
            return jsonify({'message': 'Product deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting product {id}: {e}")
            return jsonify({'error': 'Failed to delete product'}), 500


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

@app.route('/categories', methods=['GET'])
def get_categories():
    return jsonify(CATEGORIES), 200
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'message': 'File uploaded successfully', 'image_url': f'/uploads/{filename}'})

    else:
        return jsonify({'error': 'File type not allowed'}), 400
    


@app.route('/upload-image', methods=['POST'])
@admin_required
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    # Create a unique filename
    filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Assuming images will be served from /uploads/
    image_url = f'/uploads/{filename}'

    return jsonify({'message': 'Image uploaded successfully', 'image_url': image_url}), 201
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
