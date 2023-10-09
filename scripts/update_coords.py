import sys
sys.path.insert(1, '/home/mag/Projects/igps_app')
from mongoengine import *
import requests
import time
import json
import operator
from shapely.geometry import Point, Polygon

# connect to db
connect(db="sttechdb", host="127.0.0.1", port=27017)

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

class LatestSpotMessages(Document):
    username=StringField()
    feedId=StringField()
    latest_message = DictField()
    messengerId=StringField()

class GeoEdge(Document):

    id = IntField(primary_key=True,min_value=1254)
    user = ReferenceField(NewUsers)
    vertices = ListField() # list of points
    edges = ListField() # list of edges

def is_inzone(asset: Asset):

    print("Check whether in zone")

    # geo zabor

    t = asset.user

    geoedge_obj = GeoEdge.objects().filter(user=t)

    

    geoedge = json.loads(geoedge_obj.to_json())
    
    print(geoedge)
    
    if len(geoedge) <= 0:
        return True
    else:
        print(len(geoedge))

        geoedge[0]["vertices"].sort(key=operator.itemgetter("pos"))

        #create a list of Points
        points = []
        for el in geoedge[0]["vertices"]:
            points.append(Point(el["lat"], el["lng"]))

        # create a polygon
        poly = Polygon([[p.x, p.y] for p in points])

        asset_point = Point(asset["current_lat"], asset["current_lng"])

        return poly.contains(asset_point)

def add_assets():

    print("Call add asset")
    url = "http://127.0.0.1:5001/add_assets"
    data = {
        "username": "empty"                
    }
    
    x = requests.post(url, json = data)
    a = x.json()
    print(a["message"])
    time.sleep(1)

add_assets()

#read from latest_spot_messages
latest_message_col = LatestSpotMessages.objects().as_pymongo()
delisted_esns = ["0-4346707","0-4360733","0-3183728","0-4346883","0-4369446","0-4352674","0-2689338", "0-4390940"]
print(len(latest_message_col))
for i in range(len(latest_message_col)):
    print(latest_message_col[i]["latest_message"])
    
    if latest_message_col[i]["messengerId"] in delisted_esns:
        continue
    
    device = Device.objects.get(messenger_id=latest_message_col[i]["messengerId"])
    print(device["messenger_id"])
    print(latest_message_col[i]["latest_message"]["latitude"])
    print(latest_message_col[i]["latest_message"]["longitude"])
    print(latest_message_col[i]["latest_message"]["dateTime"])
    print(latest_message_col[i]["latest_message"]["messengerName"])
    asset = Asset.objects.get(device=device)
    print(asset["asset_name"])
  
    zone_status = is_inzone(asset)

    Asset.objects(device=device).update(
        current_lat = latest_message_col[i]["latest_message"]["latitude"],
        current_lng = latest_message_col[i]["latest_message"]["longitude"],
        datetime = latest_message_col[i]["latest_message"]["dateTime"],
        battery_status = latest_message_col[i]["latest_message"]["batteryState"],
        is_inzone = zone_status,
        is_notified = False
    )

#add_assets()




