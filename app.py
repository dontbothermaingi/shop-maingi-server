from models import db, User, RevokedToken, CustomerAddress, Product, KeyFeature, Specification, Cart, CartItem, Order, OrderItem
from flask import Flask,request, jsonify, make_response, send_from_directory
from werkzeug.security import check_password_hash,generate_password_hash
from flask_migrate import Migrate
from flask_cors import cross_origin, CORS
from flask_bcrypt import bcrypt
import os
from datetime import datetime
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token,create_refresh_token, get_jwt_identity,jwt_required, get_jwt
from sqlalchemy.orm import session
from datetime import timedelta
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False


CORS(app, supports_credentials=True, origins=['https://maingishop.netlify.app'])

migrate =  Migrate(app, db)

db.init_app(app)

api = Api(app)

# Configure secret keys
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')

# Initialize JWTManager
jwt = JWTManager(app)

# Refresh Token
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=10)  # Access token expires in 10 hours
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Image')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class UserRegister(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):

        data = request.get_json()

        username = data.get('username')
        phone_number = data.get('phone_number')
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        # Ensure that password and confirm password are strings
        password = str(password)
        confirm_password = str(confirm_password)

        # Validate user input data
        if not username or not phone_number or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password
        hashed_pw = generate_password_hash(password)

        new_user = User(
            username=username,
            phone_number=phone_number,
            email=email,
            password=hashed_pw
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        
        return jsonify({
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "phone_number": new_user.phone_number
        }), 201

api.add_resource(UserRegister, '/userRegister', endpoint='register')

class UserLogin(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        data = request.get_json(force=True)

        username = data.get('username')
        password = data.get('password')

        # Validate username and password
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # If user not found or password is incorrect
        if user is None or not check_password_hash(user.password, password):
            return jsonify({'error': 'Unauthorized, incorrect username or password'}), 401

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        print(f"Access Token: {access_token}")  # Debugging step
        print(f"Refresh Token: {refresh_token}")  # Debugging step

        # Create a response and set tokens in httpOnly cookies
        response = make_response({"message": "Login successful"})
        response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Strict')
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=True, samesite='Strict')

        # Return user details and token
        return jsonify({
            "id": user.id,
            "username": user.username,
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 201
    
    
api.add_resource(UserLogin, '/userLogin')

class CheckSession(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    @jwt_required(optional=True)  # Allow access without token but handle it explicitly
    def get(self):
        # Retrieve user ID from token if present
        user_id = get_jwt_identity()
        
        if not user_id:
            # Respond with 401 Unauthorized for clients to redirect
            return {'message': '401: Unauthorized - Login Required'}, 401
        
        # Fetch the user by ID
        user = User.query.filter(User.id == user_id).first()
        
        if user:
            return user.to_dict(), 200
        else:
            return {'message': '401: User not found'}, 401

# Add the resource to the API
api.add_resource(CheckSession, '/check_session')


class UserLogout(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        # Revoke the token
        jti = get_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        
        # Check if the token is already revoked
        existing_token = RevokedToken.query.filter_by(jti=jti).first()
        if existing_token:
            return jsonify(message="Token already revoked."), 200

        db.session.add(revoked_token)
        db.session.commit()

        # Clear the cookies
        response = make_response(jsonify(message="Logged out successfully"), 200)
        response.set_cookie('access_token', '', expires=0)
        response.set_cookie('refresh_token', '', expires=0)

        return response

# Add the logout resource to the API
api.add_resource(UserLogout, '/userLogout')


class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    @cross_origin()
    def post(self):
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)

        return {"access_token": new_access_token}, 200

    
api.add_resource(TokenRefresh, '/tokenrefresh')


class TokenRevocation(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        jti = get_jwt()['jti']  # Get JWT ID from the current token
        revoked_token = RevokedToken(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()
        return jsonify(message='Token has been revoked'), 200
    
class UserDetails(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def get(self):
        current_user_id = get_jwt_identity()

        # Fetch the user by the current_user_id
        user = User.query.filter_by(id=current_user_id).first()

        # Check if user exists
        if not user:
            return {"message": "User not found"}, 404

        # Convert the user object to a dictionary
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number
        }

        return {"user": user_data}, 200

    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def patch(self):
        current_user_id = get_jwt_identity()

        # Fetch the user by the current_user_id
        user = User.query.filter_by(id=current_user_id).first()

        # Check if user exists
        if not user:
            return {"message": "User not found"}, 404

        # Get the data from the request
        data = request.get_json()

        # Validate the incoming data
        allowed_fields = ['username', 'email', 'phone_number']
        for field in data:
            if field not in allowed_fields:
                return {"error": f"'{field}' is not a valid field."}, 400

        # Update only the fields provided in the request
        if 'username' in data and data['username']:
            user.username = data['username']
        if 'email' in data and data['email']:
            user.email = data['email']
        if 'phone_number' in data and data['phone_number']:
            user.phone_number = data['phone_number']

        # Fetch the user's cart (assuming one cart per user)
        cart = Cart.query.filter_by(user_id=current_user_id).first()

        if not cart:
            new_cart = Cart(
                user_id=current_user_id
            )
            db.session.add(new_cart)

        try:
            db.session.commit()
            # Return the updated user data
            updated_user_data = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "phone_number": user.phone_number
            }
            return {"user": updated_user_data}, 200
        except Exception as e:
            db.session.rollback()
            return {"error": f"Failed to update user: {str(e)}"}, 500

# Add the resource route
api.add_resource(UserDetails, '/userdetails')


class AddressBook(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def get(self):
        current_user_id = get_jwt_identity()
        addresses = CustomerAddress.query.filter_by(user_id=current_user_id).all()
        return jsonify([address.to_dict() for address in addresses])
        
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided for posting'}), 400

        # Required fields
        required_fields = ['first_name', 'last_name', 'phone_number', 'city']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extracting fields
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        phone_number = data.get('phone_number')
        city = data.get('city')
        street = data.get('street', '')  # Optional field
        country = data.get('country', '')  # Optional field

        # Creating a new customer address
        new_address = CustomerAddress(
            user_id=current_user_id,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            city=city,
            street=street,
            country=country,
        )

        try:
            db.session.add(new_address)
            db.session.commit()
            return jsonify(new_address.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create address: {str(e)}'}), 500
        
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def patch(self):
        current_user_id = get_jwt_identity()

        # Fetch the address for the current user
        address = CustomerAddress.query.filter_by(user_id=current_user_id).first()
        
        if address is None:
            return {"error": "Address not found."}, 404

        data = request.get_json()
        
        allowed_fields = ['first_name', 'last_name', 'city', 'street', 'country', 'phone_number']
        
        for field in data.keys():
            if field not in allowed_fields:
                return {"error": f"'{field}' is not a valid field."}, 400
            
            # Update only if the field is present and not empty
            if data[field] is not None:
                setattr(address, field, data[field])

        try:
            db.session.commit()
            return jsonify(address.to_dict()), 200  # Return updated address details
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update address: {str(e)}'}), 500


api.add_resource(AddressBook, '/addressbook')

class ProductResource(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def get(self):
        products = Product.query.all()
        return [product.to_dict() for product in products]
    
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        data = request.form
        file = request.files.get('product_image')

        # Check if an image file is provided and allowed
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'Product image is required and must be a valid file type'}), 400

        # Secure and save the filename if the file is valid
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        if not data:
            return jsonify({'error': 'No data provided for posting'}), 400

        # Validate required fields for the product
        required_fields = ['product_name', 'product_description', 'product_quantity', 'product_price']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extracting product information
        product_name = data.get('product_name')
        product_description = data.get('product_description')
        product_quantity = data.get('product_quantity')
        product_price = data.get('product_price')

        # Create new product with image
        new_product = Product(
            product_name=product_name,
            product_description=product_description,
            product_quantity=product_quantity,
            product_price=product_price,
            product_image=filename  # The image is required at this point
        )

        # Process key features
        features_data = json.loads(data.get('key_features', '[]'))
        if not features_data:
            return jsonify({'error': 'No features provided'}), 400
        
        for feature_data in features_data:
            required_feature_fields = ['description']
            for field in required_feature_fields:
                if field not in feature_data:  # Fix: Changed from 'features_data' to 'feature_data'
                    return jsonify({'error': f'Missing required field in key feature: {field}'}), 400

            description = feature_data['description']  # Fix: Changed to bracket notation

            new_feature = KeyFeature(
                description=description
            )
            new_product.key_features.append(new_feature)

        # Process specifications
        specifications_data =json.loads(data.get('specifications', []))
        if not specifications_data:
            return jsonify({'error': 'No specifications provided'}), 400
        
        for specification_data in specifications_data:
            required_specification_fields = ['header', 'content']
            for field in required_specification_fields:
                if field not in specification_data:  # Fix: Changed from 'specifications_data' to 'specification_data'
                    return jsonify({'error': f'Missing required field in specification: {field}'}), 400

            header = specification_data['header']  # Fix: Changed to bracket notation
            content = specification_data['content']  # Fix: Changed to bracket notation

            new_specification = Specification(
                header=header,
                content=content
            )
            new_product.specifications.append(new_specification)

        # Commit new product with features and specifications
        try:
            db.session.add(new_product)
            db.session.commit()
            return jsonify(new_product.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create product: {str(e)}'}), 500
        
api.add_resource(ProductResource, '/products')

@app.route('/images/<filename>')
@cross_origin(supports_credentials=True, origins=['*'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename),200


@app.route('/product/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@cross_origin(supports_credentials=True, origins=['*'])
@jwt_required()
def get_patch_and_delete_product_by_id(id):

    product = Product.query.filter_by(id=id).first()

    if not product:
        return jsonify({'error': 'Product does not exist'}), 404

    if request.method == 'GET':
        return jsonify(product.to_dict()), 200

    if request.method == 'PATCH':
        data = request.form
        file = request.files.get('product_image')

        if not data:
            return jsonify({'error': 'No data provided for update'}), 400
        
        # Check if an image file is provided and allowed
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'Product image is required and must be a valid file type'}), 400

        # Secure and save the filename if the file is valid
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        product.product_image = filename

        allowed_fields = ['product_name', 'product_description', 'product_price', 'product_image', 'product_quantity']

        items_data = json.loads(data.get('key_features', '[]'))

        if not items_data:
                return jsonify({'error': 'No items provided for the invoice'}), 400
        
        product.key_features.clear()

        for item_data in items_data:
            required_fields = ['description']
            for field in required_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required fields in item'}), 400
                

                new_key_features = KeyFeature(**item_data)
                product.key_features.append(new_key_features)
        
        specifications_data = json.loads(data.get('specifications', '[]'))
        if not specifications_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400
        
        product.specifications.clear()

        for specification_data in specifications_data:
            required_fields=['header', 'content']
            for field in required_fields:
                if field not in specification_data:
                    return jsonify({'error': f'Missing required fields in item'}), 400
                
                new_specification = Specification(**specification_data)
                product.specifications.append(new_specification)

        for key, value in data.items():
            if key in allowed_fields:
                setattr(product, key, value)

        try:
            db.session.commit()
            return jsonify(product.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update product: {str(e)}'}), 500

    if request.method == 'DELETE':
        try:
            db.session.delete(product)
            db.session.commit()
            return jsonify({'message': 'Product deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete product: {str(e)}'}), 500


class CartResource(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        cart = Cart.query.filter_by(user_id=current_user_id).first()
        
        if not cart:
            return jsonify({'error': 'Cart not found'}), 404
        
        return jsonify(cart.to_dict()), 200

    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def post(self):
        current_user_id = get_jwt_identity()

        # Fetch or create a cart
        cart = Cart.query.filter_by(user_id=current_user_id).first()
        if not cart:
            cart = Cart(user_id=current_user_id)
            db.session.add(cart)

        try:
            db.session.commit()
            return jsonify(cart.to_dict()), 201  # Cart created or fetched successfully
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create cart: {str(e)}'}), 500
    
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    def delete(self):
        """Clear all items from the current user's cart after order creation."""
        current_user_id = get_jwt_identity()
        cart = Cart.query.filter_by(user_id=current_user_id).first()
        
        if not cart:
            return jsonify({'error': 'Cart not found'}), 404

        # Delete all cart items for this cart
        try:
            CartItem.query.filter_by(cart_id=cart.id).delete()
            db.session.commit()
            return jsonify({'message': 'All items deleted from cart.'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete cart items: {str(e)}'}), 500


class CartItemResource(Resource):
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided for posting'}), 400

        # Fetch the user's cart (assuming one cart per user)
        cart = Cart.query.filter_by(user_id=current_user_id).first()

        if not cart:
            return jsonify({'error': 'Cart not found for user'}), 404

        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)  # Default quantity to 1 if not provided

        # Check for existing product in the cart
        cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()

        if cart_item:
            # If the product already exists in the cart, update the quantity
            cart_item.quantity += quantity
            cart_item_to_return = cart_item  # Assign the updated cart_item
        else:
            # If the product is not in the cart, create a new CartItem
            product = Product.query.get(product_id)
            if not product:
                return jsonify({'error': 'Product not found'}), 404

            new_cart_item = CartItem(
                cart_id=cart.id,  # Ensure you're using cart_id here
                product_id=product_id,
                quantity=quantity,
            )
            db.session.add(new_cart_item)
            cart_item_to_return = new_cart_item  # Assign the new_cart_item

        try:
            db.session.commit()
            return jsonify(cart_item_to_return.to_dict()), 200  # Return the correct cart item
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to add item to cart: {str(e)}'}), 500


api.add_resource(CartResource, '/cart')  # Define the endpoint for Cart
api.add_resource(CartItemResource, '/cartitems')  # Define the endpoint for CartItems

@app.route('/editcart/<int:product_id>', methods=['GET','PATCH','DELETE'])
@cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
@jwt_required()
def get_patch_delete_by_id(product_id):

    cartItem = CartItem.query.filter_by(product_id=product_id).first()

    if not cartItem:
        return jsonify({'error': 'Cart Item does not exist'}), 404

    if request.method == 'GET':
        return jsonify(cartItem.to_dict()), 200
    
    if request.method == 'PATCH':
        data = request.get_json()

        if not data:
            return jsonify({'error': 'There is no data to update'}), 404
        
        allowed_fields = ['quantity']

        for key,value in data.items():
            if key in allowed_fields:
                setattr(cartItem,key,value)
        
        try:
            db.session.commit()
            return jsonify(cartItem.to_dict()),200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update cart Item: {str(e)}'}), 500
        
    if request.method == 'DELETE':

        try:
            db.session.delete(cartItem)
            db.session.commit()
            return jsonify({'message': 'Cart Item deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete Cart item: {str(e)}'}), 500

class OrderResource(Resource):    
    @cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
    @jwt_required()
    def post (self):

        current_user_id = get_jwt_identity()

        data = request.get_json()

        if not data:
            return jsonify({'error': 'There is no data to post'}), 404

        required_fields = ['order_date', 'payment_method', 'delivery_method']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        # Convert date string to Python date object
        date_str = data.get('order_date')
        order_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        payment_method = data.get('payment_method')
        delivery_method = data.get('delivery_method')

        new_order = Order(
            order_date=order_date,
            payment_method=payment_method,
            delivery_method=delivery_method,
            user_id = current_user_id,
        )

        items_data = data.get('order_items')

        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields=['product_id', 'quantity']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400
        
        product_id = item_data.get('product_id')
        quantity = item_data.get('quantity')

        new_order_item = OrderItem(
            product_id=product_id,
            quantity=quantity,
        )

        new_order.order_items.append(new_order_item)

        try:
            db.session.add(new_order)
            db.session.commit()
            return jsonify(new_order.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Order: {str(e)}'}), 500

api.add_resource(OrderResource, '/neworder')

@app.route('/order/<int:id>', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
@jwt_required()
def get_order_by_id(id):
    
    current_user_id = get_jwt_identity()

    order = Order.query.filter_by(id=id, user_id=current_user_id).first()

    if not order:
        return jsonify({'error': f'Order not available'}), 404
    
    if request.method == 'GET':
        return jsonify(order.to_dict()), 200
    
@app.route('/orderitems', methods=['GET'])
@cross_origin(supports_credentials=True, origins=['https://maingishop.netlify.app'])
@jwt_required()
def get_order():
    current_user_id = get_jwt_identity()

    orders = Order.query.filter_by(user_id=current_user_id).all()

    if not orders:
        return jsonify({'error': f'Order not available'}), 404
    
    if request.method == 'GET':
        return jsonify([order.to_dict() for order in orders]), 200



if __name__ == '__main__':
    app.run(port=1904, debug=True)
