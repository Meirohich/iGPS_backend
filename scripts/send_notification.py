import sys
from mongoengine import *
from flask import Flask
from flask_pymongo import PyMongo
import firebase_admin
from firebase_admin import messaging
from firebase_admin import credentials

sys.path.insert(1, '/home/mag/Projects/igps_app')

app = Flask(__name__)

app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['MONGODB_SETTINGS'] = {
    'db': 'sttechdb',
    'host': 'localhost',
    'port': 27017
}
app.config['MONGO_URI'] = 'mongodb://localhost:27017/sttechdb'
mongo = PyMongo(app)

connect(db="sttechdb", host="127.0.0.1", port=27017)


class NewUsers(Document):

    id = IntField(primary_key=True)
    username = StringField()
    email = StringField()
    password = StringField()
    name = StringField()
    mobile = StringField()
    lang = StringField()
    firebase_token = StringField()


class Device(Document):

    id = IntField(primary_key=True)
    user = ReferenceField(NewUsers)
    device_type = StringField()
    messenger_id = StringField()


class Asset(Document):

    id = IntField(primary_key=True, min_value=1)
    user = ReferenceField(NewUsers)
    device = ReferenceField(Device)
    asset_name = StringField()
    current_lat = FloatField()
    current_lng = FloatField()
    battery_status = StringField() # GOOD or LOW
    datetime = StringField()
    is_inzone = BooleanField(default=True) # by default it is True
    is_notified = BooleanField(default=True) # by default it is True


def send_battery_notification(fcb_token, asset_name):
    send_notification(fcb_token, 'BATTERY', asset_name)


def send_zone_notification(fcb_token, asset_name):
    send_notification(fcb_token, 'ZONE', asset_name)


def send_notification(fcb_token, type, asset_name):
    print({fcb_token, type, asset_name})
    # 'type': BATTERY | ZONE,
    message = messaging.Message(
        data={
            'type': type,
            'asset': asset_name,
        },
        token=fcb_token,
    )

    try:
        response = messaging.send(message)
        print('Successfully sent message:', response)
    except Exception as e:
        print("Err", e)


def main():
    if not firebase_admin._apps:
        cred = credentials.Certificate("../private-data/igpskz-301116-firebase-adminsdk-jyprx-808a59651f.json")
        firebase_admin.initialize_app(cred)

    # For test
    # mongo.db.asset.update_many(
    #     { "$or": [ { "battery_status": "LOW" }, { "is_inzone": False } ]},
    #     { "$set": { "is_notified": False}})

    assets = list(mongo.db.asset.find({ "$or": [ { "battery_status": "LOW" }, { "is_inzone": False } ], "is_notified": False }))
    print("Asset count to be notified: ", len(assets))

    last_user_id = None
    asset_user = None
    for asset in assets:
        if last_user_id != asset["user"]:
            last_user_id = asset["user"]
            asset_user = NewUsers.objects.get(id=asset["user"])

        if asset_user.firebase_token is None or asset_user.firebase_token == "":
            continue

        if asset["is_inzone"] == False:
            send_zone_notification(asset_user.firebase_token, asset["asset_name"])

        if asset["battery_status"] == "LOW":
            send_battery_notification(asset_user.firebase_token, asset["asset_name"])

        Asset.objects.filter(id=asset["_id"]).update(
            is_notified = True
        )

main()
