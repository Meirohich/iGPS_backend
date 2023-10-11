from flask import Flask, request, jsonify
from flask_login import (current_user, LoginManager,
                             login_user, logout_user,
                             login_required, UserMixin)
from flask_mongoengine import MongoEngine
from flask_pymongo import PyMongo

db = MongoEngine()
app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['MONGODB_SETTINGS'] = {
    'db': 'sttechdb',
    'host': 'cluster0.mongodb.net',
    'port': 27017,
    'username': 'meirohich',  # Your MongoDB Atlas username
    'password': '12345',  # Your MongoDB Atlas password
    'authentication_source': 'admin',  # This is usually 'admin'
    'tls': True,  # Enable TLS/SSL encryption
    'retryWrites': True,  # Enable retryable writes
}
app.config['MONGO_URI'] = 'mongodb+srv://jstarsik200211:12345@cluster0.bggioa8.mongodb.net/sttechdb'

db.init_app(app)
mongo  = PyMongo(app)

class LatestSpotMessages(db.Document):

    username = db.StringField()
    feedId = db.StringField()
    latest_message = db.DictField()
    messengerId = db.StringField()

def func(username):

    # read username from the list
    # pull the data from latest_spot_messages
    # write to the Assets
    # 
    latest_message_col = mongo.db.latest_spot_messages
    objs = list(latest_message_col.find({"username" : username}))

    for obj in objs:

        print
    # read from the object element


if __name__ == "__main__":
    
    for message in LatestSpotMessages.objects:
        print(message.latest_message)
    username="Askar2019"

