from random import randint, choice as rc
from faker import Faker
from app import app
from models import db, RevokedToken
from datetime import datetime

fake = Faker()

with app.app_context():
    print("Deleting all records...")
   
    RevokedToken.query.delete()

    # db.session.add_all()
    db.session.commit()

    print("Items created successfully!")
