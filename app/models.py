import sys
sys.path.insert(1, '/home/gpudog/Projects/igps_app/db_folder')
from flask_login import UserMixin

from flask_mongoengine import MongoEngine

db = MongoEngine()

class NewUsers(UserMixin, db.Document):

    id = db.IntField(primary_key=True)    
    username = db.StringField()
    email = db.StringField()
    password = db.StringField()
    name = db.StringField()
    mobile = db.StringField()
    lang = db.StringField()
    firebase_token = db.StringField()

class Device(db.Document):

    id = db.IntField(primary_key=True)
    user = db.ReferenceField(NewUsers)
    device_type = db.StringField()
    messenger_id = db.StringField()


class Asset(db.Document):

    id = db.IntField(primary_key=True, min_value=1)
    user = db.ReferenceField(NewUsers)
    device = db.ReferenceField(Device)
    asset_name = db.StringField()
    color = db.StringField()
    current_lat = db.FloatField()
    current_lng = db.FloatField()
    battery_status = db.StringField() # GOOD or LOW
    is_inzone = db.BooleanField(default=True) # by default it is True
    is_notified = db.BooleanField(default=True) # by default it is True


class GeoEdge(db.Document):

    id = db.IntField(primary_key=True,min_value=1254)
    user = db.ReferenceField(NewUsers)
    vertices = db.ListField() # list of points
    edges = db.ListField() # list of edges

class LatestSpotMessages(db.Document):
    username=db.StringField()
    feedId=db.StringField()
    latest_message = db.DictField()
    messengerId=db.StringField()

def add_newasset(mongo):

    for user_object in NewUsers.objects:
        
        username = user_object.username

        latest_message_col = mongo.db.latest_spot_messages
        objs = list(latest_message_col.find({"username" : username}))

        for obj in objs:

            asset = Asset(
                id = Asset.objects.count() + 1,
                user = user_object,
                device = Device.objects.get(messenger_id=obj["messengerId"]),
                asset_name= obj["latest_message"]["messengerName"],
                current_lat = obj["latest_message"]["latitude"],
                current_lng = obj["latest_message"]["longitude"],
                battery_status = obj["latest_message"]["batteryState"]
            )
            asset.save()

def addnewusers():

    user = NewUsers(id = NewUsers.objects.count() + 1,
    username="Askar2019", email="None", password="askar2019", name="Аскар",mobile="None",lang="ru")
    user.save()

def one_query_delete_user(id):
    user = NewUsers.objects.get(id=1)
    user.delete()

def populate_newusers(mongo):

    users = mongo.db.users
    objs = list(users.find())

    for obj in objs:
        print(obj["username"])
        # user = NewUsers(
        #     id = NewUsers.objects.count() + 1,
        #     username=obj["username"],
        #     email="None",
        #     password=obj["password"],
        #     name=obj["name"],
        #     mobile="None",
        #     lang="ru"
        # )
        # user.save()


def addnewdevices(username, mongo):
 
    latest_message_col = mongo.db.latest_spot_messages
    objs = list(latest_message_col.find({"username" : username}))

    for obj in objs:
        
        device = Device(
            id=Device.objects.count()+1,
            user = NewUsers.objects.get(username=username),
            device_type = obj["latest_message"]["modelId"],
            messenger_id = obj["messengerId"]
        )
        device.save()        

def populate_device(mongo):

    for obj in NewUsers.objects:        
        addnewdevices(obj.username, mongo)



if __name__ == "__main__":
    print("Main")
    
   # addnewusers()
