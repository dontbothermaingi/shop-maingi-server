from flask import Flask
from werkzeug.security import check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    phone_number = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.String)

    customer_addresses = db.relationship('CustomerAddress', backref='user', cascade="all, delete-orphan", lazy=True)
    orders = db.relationship('Order', backref='user', cascade="all, delete-orphan", lazy=True)

    # One-to-One relationship with Cart
    cart = db.relationship('Cart', backref='user', uselist=False)
    
    
    @validates('password')
    def check_password(self,key,password):
        if len(password) < 8:
            raise ValueError('Password must be more than 8 characters.')
        return password
    
    def check_password(self,password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        return {
            "id":self.id,
            "username":self.username,
            "phone_number":self.phone_number,
            'email':self.email,
            'password':self.password,
            'customer_addresses': [address.to_dict() for address in self.customer_addresses],
        }
        

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"
    
class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)  # JWT ID
    revoked_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<User(id={self.id}')>"

class CustomerAddress(db.Model):
    __tablename__ = 'customeraddresses'

    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String)
    street = db.Column(db.String)
    country = db.Column(db.String)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    phone_number = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def to_dict(self):
        return {
            "id":self.id,
            "city":self.city,
            "street":self.street,
            'user_id': self.user_id,
            'country':self.country,
            'first_name':self.first_name,
            'last_name':self.last_name,
            'phone_number':self.phone_number,
        }
    
    def __repr__(self):
        return f"<CustomerAddress ( id={self.id})>"
    
class Product(db.Model):
    __tablename__='products'

    id = db.Column(db.Integer, primary_key=True)
    product_image = db.Column(db.String)
    product_name = db.Column(db.String, index=True)
    product_description = db.Column(db.String)
    product_quantity = db.Column(db.Integer)
    product_price = db.Column(db.Float, index=True)
    category = db.Column(db.String, nullable=True)

    key_features = db.relationship('KeyFeature', backref='product', cascade= 'all, delete-orphan', lazy='selectin' )
    specifications = db.relationship('Specification', backref='product', cascade= 'all, delete-orphan', lazy='selectin' )
    cart_items = db.relationship('CartItem', back_populates='product', lazy='selectin')  # New relationship
    order_items = db.relationship('OrderItem', back_populates='product', lazy='selectin')  # New relationship


    @validates('product_price')
    def check_price(key,self,product_price):
        try:
            # Convert product_quantity to an integer
            product_price = int(product_price)
        except (ValueError, TypeError):
            # Raise an error if the value is not a valid integer
            raise ValueError("Invalid product price. It must be a valid number.")
        
        # Check if the quantity is greater than zero
        if product_price <= 0:
            raise ValueError('Price must be greater than 0.')
        return product_price
    
    @validates('product_quantity')
    def check_quantity(self, key, product_quantity):
        try:
            # Convert product_quantity to an integer
            product_quantity = int(product_quantity)
        except (ValueError, TypeError):
            # Raise an error if the value is not a valid integer
            raise ValueError("Invalid product quantity. It must be a valid number.")
        
        # Check if the quantity is greater than zero
        if product_quantity <= 0:
            raise ValueError("Product quantity must be greater than 0.")
        
        return product_quantity


    def to_dict(self):
        return {
            "id": self.id,
            "product_name": self.product_name,
            "product_image": f"/images/{self.product_image}",
            "product_description": self.product_description,
            "product_quantity": self.product_quantity,
            "category":self.category,
            "product_price": self.product_price,
            "key_features": [feature.to_dict() for feature in self.key_features],
            "specifications": [specification.to_dict() for specification in self.specifications]
        }
    
    def __repr__(self):
        return f"<Product ( id={self.id}, product_name={self.product_name}, product_description={self.product_description}, product_quantity={self.product_quantity}, product_price={self.product_price} ) >"

class KeyFeature(db.Model):
    __tablename__ = 'keyfeatures'

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)


    def to_dict(self):
        return{
            "id":self.id,
            "description":self.description
        }
    
    def __repr__(self):
        return f"<KeyFeature (id={self.id}, description={self.description} )>"
    
class Specification(db.Model):
    __tablename__='specifications'

    id = db.Column(db.Integer, primary_key=True)
    header = db.Column(db.String)
    content = db.Column(db.String)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False, index=True)


    def to_dict(self):
        return {
            "id":self.id,
            "header":self.header,
            "content":self.content,
        }
    
    def __repr__(self):
        return f"<Specification (id={self.id}, header={self.header}, content={self.content} )>"

class Cart(db.Model):
    __tablename__ = 'carts'

    id = db.Column(db.Integer, primary_key=True)
    cart_items = db.relationship('CartItem', backref='cart', cascade='all, delete-orphan', lazy='selectin')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)

    @property
    def cart_amount(self):
        return sum(item.product.product_price * item.quantity for item in self.cart_items)
    
    @property
    def cart_quantity(self):
        return sum(item.quantity for item in self.cart_items)


    def to_dict(self):
        return {
            'id': self.id,
            'cart_amount': self.cart_amount,
            'cart_quantity': self.cart_quantity,
            'products': [
                {
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_price': item.product.product_price,
                    'total_price': item.product.product_price * item.quantity,
                    'product_name': item.product.product_name,
                    'product_image': f"/images/{item.product.product_image}",  # Adjust as necessary
                    'product_description': item.product.product_description,
                    "product_quantity": item.product.product_quantity,

                }
                for item in self.cart_items
            ]
        }
    
    def __repr__(self):
        return f"<Cart( id={self.id})>"

class CartItem(db.Model):
    __tablename__ = 'cart_items'

    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('carts.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

    product = db.relationship('Product', back_populates='cart_items')

    def to_dict(self):
        # Access the related Product's attributes
        return {
            "product_id": self.product_id,
            "quantity": self.quantity,
            "product_price": self.product.product_price,  # Reference the price from the Product model
            "total_price": self.product.product_price * self.quantity,
            "product_name": self.product.product_name,
            "product_image": f"/images/{self.product.product_image}",
            "product_description": self.product.product_description,
        }
    
    def __repr__(self):
        return f"<CartItem( id={self.id})>"

class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_date = db.Column(db.Date)
    payment_method = db.Column(db.String)
    delivery_method = db.Column(db.String)
    city = db.Column(db.String)
    street = db.Column(db.String)
    country = db.Column(db.String)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    phone_number = db.Column(db.String)


    order_items = db.relationship('OrderItem', backref='order', cascade="all, delete-orphan", lazy=True)

    @property
    def order_amount(self):
        return sum(item.product.product_price * item.quantity for item in self.order_items)
    
    @property
    def order_quantity(self):
        return sum(item.quantity for item in self.order_items)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id':self.user_id,
            'order_date':self.order_date,
            'payment_method':self.payment_method,
            'delivery_method':self.delivery_method,
            'order_amount':self.order_amount,
            'order_quantity':self.order_quantity,
            "city":self.city,
            "street":self.street,
            'user_id': self.user_id,
            'country':self.country,
            'first_name':self.first_name,
            'last_name':self.last_name,
            'phone_number':self.phone_number,
            'products': [
                {
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_price': item.product.product_price,
                    'total_price': item.product.product_price * item.quantity,
                    'product_name': item.product.product_name,
                    'product_image': f"/images/{item.product.product_image}",  # Adjust as necessary
                    'product_description': item.product.product_description,
                    "product_quantity": item.product.product_quantity,

                }
                for item in self.order_items
            ]
        }
    
    def __repr__(self):
        return f"<Order ( id={self.id}, order_date={self.order_date,} payment_method={self.payment_method}, delivery_method={self.delivery_method} )>"


class OrderItem(db.Model):
    __tablename__ = 'order_items'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

    product = db.relationship('Product', back_populates='order_items')


    def to_dict(self):
        return {
            'id': self.id,
            'product_id':self.product_id,
            "product_price": self.product.product_price,  # Reference the price from the Product model
            "total_price": self.product.product_price * self.quantity,
            "product_name": self.product.product_name,
            "product_image": f"/images/{self.product.product_image}",
            "product_description": self.product.product_description,
            "quantity": self.quantity
        }
    
    def __repr__(self):
        return f"<OrderItem ( id={self.id}, product_id={self.product_id}, quantity={self.quantity} )>"


    


