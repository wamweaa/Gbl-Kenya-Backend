from datetime import date, timedelta
from app import db, User, Product, Cart,  app  # Use 'Deal' instead of 'DealOfTheWeek'


with app.app_context():  # Ensure the script runs inside Flask's app context
    # Delete existing data in a safe order
    db.session.query(Cart).delete()

    db.session.query(Product).delete()
    db.session.query(User).delete()
    db.session.commit()

    # Create sample users
    users = [
        User(username="john_doe", password="$2b$12$3lXoVbDyzE6Fn1R5z5KQFuvzXpj5OFTbPl6.0sHKj3Rm1j/8VHg1O"),
        User(username="jane_smith", password="$2b$12$3lXoVbDyzE6Fn1R5z5KQFuvzXpj5OFTbPl6.0sHKj3Rm1j/8VHg1O"),
    ]
    db.session.add_all(users)
    db.session.commit()

    # Fetch users dynamically after commit
    john = User.query.filter_by(username="john_doe").first()
    jane = User.query.filter_by(username="jane_smith").first()

    if not john or not jane:
        raise ValueError("Users not found! Ensure users are created properly.")

    # Create sample products
    products = [
        Product(name="Yamaha Grand Piano", description="High-quality grand piano with amazing sound.",
                price=5000.99, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=5, category="Piano"),
        
        Product(name="Roland Digital Keyboard", description="Compact and versatile digital keyboard.",
                price=799.99, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=10, category="Keyboards"),
        
        Product(name="Fender Stratocaster Guitar", description="Classic electric guitar loved by professionals.",
                price=1200.50, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=7, category="Guitars"),
        
        Product(name="Pioneer DJ Controller", description="Perfect DJ setup for professionals and beginners.",
                price=950.00, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=4, category="DJ Equipment"),
        
        Product(name="Shure SM58 Microphone", description="Industry-standard dynamic microphone for vocals.",
                price=99.99, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=20, category="PA Equipment"),
        
        Product(name="Yamaha Drum Kit", description="Complete drum set for drummers of all levels.",
                price=1300.00, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=3, category="Drums"),
        
        Product(name="Ableton Live Software", description="Industry-leading music production software.",
                price=599.99, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=50, category="Music Production"),
        
        Product(name="Bose Sound System", description="Premium sound system for concerts and events.",
                price=2500.00, image_url="https://imgs.search.brave.com/gciekIDf4JlR6U-eEwmZFFHkIBu3Z7E1sMUtnrwZF2U/rs:fit:500:0:0:0/g:ce/aHR0cHM6Ly90NC5m/dGNkbi5uZXQvanBn/LzAyLzIyLzU0LzUz/LzM2MF9GXzIyMjU0/NTMxOV82blJpclB3/SnN4d0VpRUI0N0lE/ZVFOOU5OZGZscDVT/bS5qcGc", stock=2, category="Audio & Visual"),
    ]
    db.session.add_all(products)
    db.session.commit()

    # Fetch products dynamically
    keyboard = Product.query.filter_by(name="Roland Digital Keyboard").first()
    microphone = Product.query.filter_by(name="Shure SM58 Microphone").first()
    guitar = Product.query.filter_by(name="Fender Stratocaster Guitar").first()
    dj_controller = Product.query.filter_by(name="Pioneer DJ Controller").first()

    if not keyboard or not microphone or not guitar or not dj_controller:
        raise ValueError("One or more products not found! Ensure products are created properly.")

    # Create sample cart items
    cart_items = [
        Cart(user_id=john.id, product_id=keyboard.id, quantity=1),
        Cart(user_id=john.id, product_id=microphone.id, quantity=2),
        Cart(user_id=jane.id, product_id=guitar.id, quantity=1),
    ]
    db.session.add_all(cart_items)
    db.session.commit()



    print("Database seeded successfully, including 'Deals of the Week'!")
