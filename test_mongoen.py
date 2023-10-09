from flask import Flask, request, jsonify
from flask_login import (current_user, LoginManager,
                             login_user, logout_user,
                             login_required, UserMixin)
from flask_mongoengine import MongoEngine
from flask_pymongo import PyMongo

db = MongoEngine()
app = Flask(__name__)

app.config['MONGODB_SETTINGS'] = {
    'db': 'sttechdb',
    'host': 'localhost',
    'port': 27017
}
app.config['MONGO_URI'] = 'mongodb://localhost:27017/sttechdb'

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

