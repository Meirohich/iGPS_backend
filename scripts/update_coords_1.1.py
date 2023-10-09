import sys
sys.path.insert(1, '/home/mag/Projects/igps_app')
from mongoengine import *

# connect to db
connect(db="testdb", host="127.0.0.1", port=27017)

# pull the data form collection latest_spot_messages
# update the Asset information
class NewUsers(Document):

    id = IntField(primary_key=True)    
    username = StringField()
    email = StringField()
    password = StringField()
    name = StringField()
    mobile = StringField()
    lang = StringField()

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

class LatestSpotMessages(Document):
    username=StringField()
    feedId=StringField()
    latest_message = DictField()
    messengerId=StringField()

 
# read from latest_spot_messages
latest_message_col = LatestSpotMessages.objects().as_pymongo()
print(len(latest_message_col))
for i in range(len(latest_message_col)):
    #print(latest_message_col[i]["latest_message"])
    device = Device.objects.get(messenger_id=latest_message_col[i]["messengerId"])
    print(device["messenger_id"])
    print(latest_message_col[i]["latest_message"]["latitude"])
    print(latest_message_col[i]["latest_message"]["longitude"])
    print(latest_message_col[i]["latest_message"]["dateTime"])
    asset = Asset.objects.get(device=device)
    print(asset["asset_name"])
    Asset.objects(device=device).update(
        current_lat = latest_message_col[i]["latest_message"]["latitude"],
        current_lng = latest_message_col[i]["latest_message"]["longitude"],
        datetime = latest_message_col[i]["latest_message"]["dateTime"]
    )





