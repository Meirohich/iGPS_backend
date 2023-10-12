import sys
sys.path.insert(1, '/home/mag/Projects/igps_app')
import utils
from flask import Flask, request, Response, jsonify, make_response, abort
from flask_login import LoginManager
from models import *
from flask_pymongo import PyMongo
from shapely.geometry import Point, Polygon

from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import json
import operator
import random
import base64
from datetime import datetime

import firebase_admin
from firebase_admin import messaging
from firebase_admin import credentials

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
print(f"MongoDB URI: {app.config['MONGO_URI']}")
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

try:
    # Attempt to connect to MongoDB Atlas
    mongo = PyMongo(app)
except Exception as e:
    print(f"Error connecting to MongoDB Atlas: {str(e)}")


@app.route('/test_mongodb_connection')
def test_mongodb_connection():
    # data = mongo.db.new_users.find_one()
    try:
        data = mongo.db.new_users.find_one()
        if data:
            return jsonify({'message': 'MongoDB connection successful', 'data': data})
        else:
            return jsonify({'message': 'No data found in the collection'})
    except Exception as e:
        return jsonify({'message': f'MongoDB query error: {str(e)}'})

    # if data:
    #     return jsonify({'message': 'MongoDB connection successful', 'data': data})
    # else:
    #     return jsonify({'message': 'MongoDB connection failed'})

@app.route('/')
def index():
      return "Hello world!"


@app.route('/payment')
def payment():
    command = request.args.get('command')
    args = request.args
    if command == 'check' and len(args) == 4:
        return check(args)
    elif command == 'pay' and len(args) == 5:
        return pay(args)
    else:
        return jsonify({'message': 'invalid request'}), 400


def check(args):
    txn_id = args.get('txn_id')
    account = args.get('account')
    sum = args.get('sum')

    js_data = jsonify({'txn_id': txn_id,
                        'result': 0,
                        'comment': ''})
    return js_data


def pay(args):
    txn_id = args.get('txn_id')
    txn_date = args.get('txn_date')
    account = args.get('account')
    sum = args.get('sum')

    js_data = jsonify({'txn_id': txn_id,
                        'prv_txn_id': 'id of payment document',
                        'result': 0,
                        'sum': sum,
                        'comment': 'OK'})
    return js_data

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        print(token)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(data)
            new_users = mongo.db.new_users
            current_user = new_users.find_one({'_id':data['id']})
            # current_user = NewUsers.objects.get(id=data['id'])
            print(current_user['_id'])
        except:
            return jsonify({'message': 'token is invalid'}), 415

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/dev_to_lat',methods=['POST'])
def dev_to_lat():


    #if request.remote_addr != '127.0.0.1':
    #   abort(403)

    data = request.get_json()
    print(data)
    username = data["username"]

    devices = mongo.db.devices
    objs = list(devices.find({"username" : username}))

    if not objs:
        print("Objs is empty")
        return jsonify({'message':'no devices for this username'})

    print("Len of objs: " + str(len(objs)))
    print("Username: " + str(username))

    messengerNameId = 1
    for obj in objs:

        print("new object")
        #print(obj)
        #print(obj["esn"])

        messages = obj["messages"]
        newlist = sorted(messages, key=lambda k: k['unixTime'])

        print("----start---")
        #print(messages)
        print("------------")

        print("---- IF ----")
        if len(newlist) > 0:

            print(newlist[-1])

            obj_time = newlist[-1]["timeStamp"]
            datetime_object = datetime.strptime(obj_time,'%d/%m/%Y %H:%M:%S %Z')
            latest_mess_time = datetime_object.strftime("%Y-%m-%dT%H:%M:%S+0000")
            messengerName = "GPS " + str(messengerNameId)

            pay = newlist[-1]["payload"]
            if pay.find("0x5") != -1 or pay.find("0xC") !=-1 or pay.find("0x4") != -1:
                continue

            batSt, lat, lng= utils.decodeStPay(newlist[-1]["payload"])
            print(lng)
            print(lat)
            print(batSt)
            print(latest_mess_time)
            print ("Insert or update " + obj["esn"])
            result = mongo.db.latest_spot_messages.update_one(
                {"messengerId": obj["esn"]},
                {
                    "$set": {
                        "username": username,
                        "feedId": "empty",
                        "latest_message": {
                            "id": 2346,
                            "messengerId": obj["esn"],
                            "messageType": "default",
                            "altitude": 0,
                            "dateTime": latest_mess_time,
                            "latitude": lat,
                            "longitude": lng,
                            "unixTime": newlist[-1]["unixTime"],
                            "batteryState": batSt,
                            "modelId": "SMARTONE",
                            "messengerName": messengerName
                        },
                        "messengerId": obj["esn"]
                    }
                },
                upsert=True
            )

            #mongo.db.latest_spot_messages.update(
            #        {"messengerId":obj["esn"]},
            #        {"$set": {"username":username,"feedId":"empty", "latest_message": {
            #            "id": 2344, "messengerId" : obj["esn"], "messageType" : "default", "altitude" : 0,"dateTime": latest_mess_time, "latitude": lat,"longitude": lng,"unixTime": newlist[-1]["unixTime"], "batteryState": batSt,"modelId": "SMARTONE","messengerName":messengerName }, "messengerId": obj["esn"]}},upsert=True)

        messengerNameId = messengerNameId + 1


    return jsonify({'message':'successful return'})


@app.route('/reg_smartone',methods=['POST'])
def reg_smartone():

    # if request.remote_addr != '127.0.0.1':
    #    abort(403)

    data = request.get_json()
    username = data["username"]

    # userid = data['userid']
    esni = data['esn']
    # создание новой записи в коллекции устройств devices
    # esn серийного номера устройства
    # обновление esn userprofile или добавление нового документа asset
    # check whether this messengerId exists in the Devices collection
    # if it does not exist then insert

    # if mongo.db.devices.find({'esn': esni}).count() > 0:
    if mongo.db.devices.count_documents({'esn': esni}) > 0:
        return jsonify({'message': "ESN " + esni + " already exists in the devices"})

    count = mongo.db.devices.count_documents({})
    new_device_document = {
        "_id": count + 16,
        "esn": esni,
        "username": username,
        "messages": []
    }
    # mongo.db.devices.insert_one({"_id":mongo.db.devices.count()+16, "esn":esni, "username":username,"messages":[]})
    mongo.db.devices.insert_one(new_device_document)
    js_data=jsonify({'message': 'devices registered successfully'})
    return js_data

@app.route("/reg_smartone_c", methods=['POST'])
def reg_smartone_c():

    if request.remote_addr != '127.0.0.1':
        abort(403)

    data = request.get_json()
    username = data['username']
    esns = data["esns"]



@app.route('/is_registered', methods=[ 'POST'])
def is_registered():
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden

    data = request.get_json()
    username = data["username"]

    if NewUsers.objects(username__contains=username).count() > 0:
        js_data=jsonify({'message': True})
    else:
        js_data=jsonify({'message': False})

    return js_data


@app.route('/reg', methods=[ 'POST'])
def reg():
    # if request.remote_addr != '127.0.0.1':
    #     abort(403)  # Forbidden

    data = request.get_json()

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    count = mongo.db.new_users.count_documents({})
    new_user_document = {
        "_id": count + 6,
        "username": data['username'],
        "email": data['email'],
        "password": hashed_password,
        "name": data['name'],
        "mobile": data['mobile'],
        "lang": data['lang'],
        "firebase_token": 1
    }

    mongo.db.new_users.insert_one(new_user_document)
    # new_users = mongo.db.new_users
    # newuser = new_users.insert({
    #         "_id" : count + 6,
    #         "username": data['username'],
    #         "email":  data['email'],
    #         "password":  hashed_password,
    #         "name" : data['name'],
    #         "mobile" : data['mobile'],
    #         "lang" :  data['lang'],
    #         "firebase_token": 1})
    s = "Total number of users: " + str(mongo.db.new_users.count_documents({}))
    print(s)

    js_data=jsonify({'message': 'registered successfully'})

    return js_data


def register_user(_username, _password, _name, _mobile, _lang, _email):

    password = bcrypt.generate_password_hash(_password).decode('utf-8')
    new_users = mongo.db.new_users
    user_id = new_users.insert({
        'name'       : _name,
        'username'   : _username,
        'password'   : password,
        'created'    : datetime.now()
        })

    new_user = new_users.find_one({'_id': user_id})

    result = {'email': new_user['name'] + ' is registered'}

    return jsonify({'result' : result})


@app.route('/login', methods=['POST'])
def login_user():

    # auth = request.authorization
    auth = request.headers.get('Authorization')

    #if not auth or not auth.username or not auth.password:
    if not auth or not auth.startswith('Basic '):
        return make_response(
            'could not verify',
            401,
            {'WWW.Authentication': 'Basic realm: "login required"'}
        )

    auth = auth[6:]  # Remove 'Basic ' prefix
    credentials = base64.b64decode(auth).decode('utf-8')

    username, password = credentials.split(':')
    print(username + ' ' + password)
    new_users = mongo.db.new_users
    user = new_users.find_one({'username': username})
    # user = NewUsers.objects.get(username=username)
    print(user['_id'])
    if bcrypt.check_password_hash(user['password'], password):
        token = jwt.encode(
            {
                'id': user['_id'],
                'exp' : datetime.utcnow() + timedelta(minutes=30)
            },
            app.config['SECRET_KEY']
        )#.decode('utf-8')
        update_data = {'$set': {'firebase_token': 1}}
        result = new_users.update_one(user, update_data)
        return jsonify({'token': token, 'name': user['name'], 'email': user['email'], '_id': user['_id']})

    return make_response(
        'could not verify',
        401,
        {'WWW.Authentication': 'Basic realm: "login required"'}
    )


@app.route('/logout', methods=['POST'])
@token_required
def logout_user(current_user):
    print("Logout user: ")
    print(current_user['_id'])
    new_users = mongo.db.new_users
    update_data = {'$set': {'firebase_token': None}}
    result = new_users.update_one(current_user, update_data)
    if result.modified_count > 0:
        js_data = jsonify({'message': 'updated successfully'})
        return js_data
    else:
        return jsonify({'message': "User not found or no changes made."})

    #NewUsers.objects(id=current_user.id).update(
    #    firebase_token=None)


@app.route('/assets', methods=['GET'])
@token_required
def get_assets(current_user):

    # check whether assets are in zone and update the is_inzone field in the database
    #is_inzone(current_user)
    assets_db = mongo.db.asset
    user_id = current_user['_id']
    assets_cursor = assets_db.find({'user': user_id})
    # assets = Asset.objects().filter(user=current_user).to_json()

    print(assets_cursor)
    print("-----")

    json_assets = []
    for asset in assets_cursor:
        # asset_dict = json.loads(asset)
        json_assets.append(asset)

    #data = json.loads(assets)
    ret_assets = []
    for assets in json_assets:
        print(assets)
        devices_db = mongo.db.device
        device_id = assets['device']
        device_cursor = devices_db.find({'_id': device_id})
        json_devices = []
        for device in device_cursor:
            json_devices.append(device)
        # device = Device.objects().filter(id=int(asset['device'])).to_json()
        # device = json.loads(device)
        print("DEVICE")
        print(device_cursor)

        assets['esn']=json_devices[0]['messenger_id']
        assets['device_type']=json_devices[0]['device_type']
        ret_assets.append(assets)

    js_data=jsonify(ret_assets)

    return js_data
    #return Response(assets, mimetype="application/json", status=200)

@app.route('/uassets/<int:id>', methods=['PUT'])
@token_required
def update_assets(current_user, id):

    print("update Edges")

    data = request.get_json()
    print(data['asset_name'])
    Asset.objects(id=data['_id']).update(
        asset_name=data['asset_name'], # list of points with coordinates
        #color=data['color']
   )

    js_data=jsonify({'message': 'updated successfully'})

    return js_data

@app.route('/cmark', methods=['POST'])
@token_required
def create_marks(current_user):

    print("add mark")

    data = request.get_json()

    marks_col = mongo.db.marks
    print(current_user['id'])

    random.seed(datetime.datetime.now())

    data = {
        "_id":random.randint(1,10000) + 3,
        "userid": current_user['id'],
        "username": current_user['username'],
        "mark_name" : data['mark_name'],
        "mark_type" : data['mark_type'],
        "mark_lat": data["mark_lat"],
        "mark_lng": data["mark_lng"]
    }
    rec_id = marks_col.insert_one(data).inserted_id
    print(rec_id)
    #rec_id = 1
    js_data=jsonify({'message': 'registered successfully',"db_id":str(rec_id)})

    return js_data

@app.route('/rmark', methods=['GET'])
@token_required
def read_marks(current_user):

    print("read Mark")
    print(current_user['username'])
    #data = request.get_json()

    marks_col = mongo.db.marks

    objs = list(marks_col.find({"username" : current_user['username']}))

    print(objs)

    i = 1

    #for obj in objs:
    #    obj["_id"] =
    #    i = i + 1

    js_data=jsonify(objs)

    return js_data

@app.route('/umark/<int:id>', methods=['PUT'])
@token_required
def update_marks(current_user, id):

    print("update Edges")

    data = request.get_json()
    marks_col = mongo.db.marks

    marks_col.update_one({"_id":id},
            {"$set": {
                "mark_name" : data['mark_name'],
                "mark_type" : data['mark_type'],
                "mark_lat": data["mark_lat"],
                "mark_lng": data["mark_lng"]
              }
            })

    js_data=jsonify({'message': 'updated successfully'})

    return js_data

@app.route('/dmark/<int:id>', methods=['DELETE'])
@token_required
def delete_marks(user,id):

    print("delete Edges")

    marks_col = mongo.db.marks

    marks_col.delete_one({"_id":id})

    js_data=jsonify({'message': 'deleted successfully'})

    return js_data




@app.route('/cedges', methods=['POST'])
@token_required
def add_edges(current_user):

    print("add Edges")

    data = request.get_json()


    geoedge = GeoEdge(
        id=GeoEdge.objects.count() + 1254,
        user=current_user,
        vertices=data['vertices'] # list of points with coordinates
        #edges=data['edges'] # list of pair of coordinates
    )
    geoedge.save()

    js_data=jsonify({'message': 'registered successfully'})

    return js_data

@app.route('/redges', methods=['GET'])
@token_required
def read_edges(current_user):

    print("read Edges")

    #data = json.loads(request.data)

    geoedge = GeoEdge.objects().filter(user=current_user).to_json()

    return Response(geoedge, mimetype="application/json", status=200)

@app.route('/uedges/<int:id>', methods=['PUT'])
@token_required
def update_edges(current_user, id):

    print("update Edges")

    data = request.get_json()

    GeoEdge.objects(id=data['_id']).update(
        vertices=data['vertices'] # list of points with coordinates
    )

    js_data=jsonify({'message': 'updated successfully'})

    return js_data

@app.route('/dedges/<int:id>', methods=['DELETE'])
@token_required
def delete_edges(user,id):

    print("delete Edges")

    #data = json.loads(request.data)

    #obj = GeoEdge.objects.get(id=data['gedgeid']) # list of points with coordinates
    obj = GeoEdge.objects().filter(id=id)

    obj.delete()

    js_data=jsonify({'message': 'deleted successfully'})

    return js_data


#@app.route('/is_inzone', methods=['GET'])
#@token_required
def is_inzone(current_user):

    print("Check whether in zone")

    # geo zabor
    geoedge = json.loads(GeoEdge.objects().filter(user=current_user).to_json())

    # list of assets
    assets = json.loads(Asset.objects().filter(user=current_user).to_json())

    points = []
    print(geoedge)
    if len(geoedge) > 0:
        geoedge[0]["vertices"].sort(key=operator.itemgetter("pos"))

        # create a list of Points
        for el in geoedge[0]["vertices"]:
            points.append(Point(el["lat"], el["lng"]))

        # create a polygon
        poly = Polygon([[p.x, p.y] for p in points])

        print(assets)
        list_dict_assets = []

        for asset in assets:
            asset_point = Point(asset["current_lat"], asset["current_lng"])
            print(asset_point)
            print(poly.contains(asset_point))
            dict_asset = {
                "id": asset["_id"],
                "is_inzone": poly.contains(asset_point)
            }
            list_dict_assets.append(dict_asset)
            Asset.objects(id=asset["_id"]).update(
                is_inzone=dict_asset["is_inzone"]
            )

@app.route('/reg_devices', methods=[ 'POST'])
def reg_devices():
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden

    data = request.get_json()
    username = data["username"]
    latest_message_col = mongo.db.latest_spot_messages
    objs = list(latest_message_col.find({"username" : username}))
    print(objs)
    print("Len of objs: " + str(len(objs)))
    print("Username: " + str(username))
    for obj in objs:

        print(obj["latest_message"]["modelId"])
        messengerId = obj["messengerId"]
        if Device.objects(messenger_id__contains=messengerId).count() > 0:
            print("Yes")
        else:
            print("No")

        # check whether this messengerId exists in the Devices collection
        # if it does not exist then insert

            device = Device(
                id=Device.objects.count()+20,
                user = NewUsers.objects.get(username=username),
                device_type = obj["latest_message"]["modelId"],
                messenger_id = obj["messengerId"]
            )
            device.save()

    s = "Total number of devices: " + str(Device.objects.count())
    #print(s)
    js_data=jsonify({'message': 'devices registered successfully'})

    return js_data

@app.route('/history',methods=['POST'])
@token_required
def selectLastNMsg(current_user):
    # select k messages(t1,..tk) in devices collection from Clients


    #print(request.data)
    #print("------")
    data = json.loads(request.data)

    #print(data['esn'])
    #print(data['number_of_points'])

    esni = data['esn']
    k = data['number_of_points']

    # check from device which type

    devicetype = mongo.db.device.find({"messenger_id":data['esn']})
    l_dev = list(devicetype)
    #print(l_dev[0])

    js_data = []
    if l_dev[0]['device_type'] == "SMARTONE":
        #print(True)
        #print(k)
        lastmss = mongo.db.devices.aggregate([
            { "$match":{"esn": esni} },
            { "$project":{"_id":0, "esn":1, "messages":1} },
            { "$unwind": "$messages"},
            { "$sort": {"messages.unixTime": -1} },
            {"$limit": k}
        ])

     #
        msgss = []
        #print('last k mss:::', lastmss)
        for llm in lastmss:
            #print(llm['messages'])
            payload = llm["messages"]["payload"]
            if payload.find("0x5") != -1 or payload.find("0xC") != -1 or payload.find("0x4") != -1:
                continue


            batSt, lat, lng= utils.decodeStPay(llm['messages']["payload"])
            timest = llm['messages']['timeStamp']
            datetime_object = datetime.datetime.strptime(timest,'%d/%m/%Y %H:%M:%S %Z')
            latest_mess_time = datetime_object.strftime("%Y-%m-%dT%H:%M:%S+0000")

            dic = {
              "batSt": batSt,
              "lat":lat,
              "lng":lng,
              "timestamp":latest_mess_time
            }

            msgss.append(dic)
        #print('llm',llm)
        #print('\nMSGSS:::',msgss)
        #print(len(msgss))
        #print(msgss[0])
        lnmss = list(msgss) #list(lastmss)

        #print(lnmss)
        #print("Print has been finished")
        js_data=jsonify(lnmss)

    else:
        dev = mongo.db.all_latest_messages.find({"messengerId":data['esn']})
        ldev = list(dev)
        #print(ldev)
        if (k > len(ldev[0]['messages'])):
            messages = ldev[0]['messages']
        else:
            messages = ldev[0]['messages'][-k:-1]

        print(messages)
        msgss = []

        for mess in messages:

            dic = {
                "batSt": mess['batteryState'],
                "lat": mess['latitude'],
                "lng": mess['longitude'],
                "timestamp": mess['dateTime']
            }

            msgss.append(dic)
        js_data = jsonify(msgss)

    return  js_data #Response(lnmss, mimetype="application/json", status=200)



@app.route('/add_assets', methods=[ 'POST'])
def add_newasset():

    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden

    for user_object in NewUsers.objects:

        username = user_object.username

        latest_message_col = mongo.db.latest_spot_messages
        device_col = mongo.db.device
        objs = list(latest_message_col.find({"username" : username}))

        #print(username)
        for obj in objs:
            print(obj["messengerId"])

            #tt =device_col.find_one({"messenger_id":obj["messengerId"]})
            #print(tt)

            if Asset.objects(device__contains=Device.objects.get(messenger_id=obj["messengerId"])).count() > 0:
                print("Yes, asset " + obj["latest_message"]["messengerName"] + " already exists")
            else:
                print("No, asset " + obj["latest_message"]["messengerName"] + " is not registered")

                asset = Asset(
                    id = Asset.objects.count() + 32,
                    user = user_object,
                    device = Device.objects.get(messenger_id=obj["messengerId"]),
                    asset_name= obj["latest_message"]["messengerName"],
                    current_lat = obj["latest_message"]["latitude"],
                    current_lng = obj["latest_message"]["longitude"],
                    battery_status = obj["latest_message"]["batteryState"],
                    is_notified = True
                )
                asset.save()

    s = "Total number of assets: " + str(Asset.objects.count())

    #print(s)
    js_data=jsonify({'message': 'devices registered successfully'})

    return js_data


@app.route('/notifications')
def get_notifications():

    if not firebase_admin._apps:
        cred = credentials.Certificate("../private-data/igpskz-301116-firebase-adminsdk-jyprx-808a59651f.json")
        firebase_admin.initialize_app(cred)

    user = NewUsers.objects().get(id=11)

    registration_token = user.firebase_token

    #print(registration_token)
    # 'type': BATTERY | ZONE,
    message = messaging.Message(
        data={
            'type': 'BATTERY',
            'asset': 'Horse',
        },
        token=registration_token,
    )

    try:
        response = messaging.send(message)

        #print('Successfully sent message:', response)
        return response
    except Exception as e:
        print("Err", e)
        return str(e)


@app.route('/set/firebase/token', methods=['POST'])
@token_required
def set_firebase_token(current_user):
    print("Set FCM token", request.data)
    data = json.loads(request.data)
    firebase_token = data['firebase_token']
    NewUsers.objects(id=current_user.id).update(
        firebase_token=firebase_token
    )

    js_data = jsonify({'message': 'updated successfully'})

    return js_data

@app.route('/send/fake/firebase/notification', methods=['POST'])
@token_required
def send_fake_notification(current_user):
    print("Set FCM token", request.data)
    data = json.loads(request.data)
    firebase_token = data['firebase_token']
    NewUsers.objects(id=current_user.id).update(
        firebase_token=firebase_token
    )

    if not firebase_admin._apps:
        cred = credentials.Certificate("../private-data/igpskz-301116-firebase-adminsdk-jyprx-808a59651f.json")
        firebase_admin.initialize_app(cred)

    message = messaging.Message(
        data={'type': 'test', 'asset': 'Testing notification'},
        token=firebase_token,
    )

    try:
        response = messaging.send(message)
        print('Successfully sent message:', response)
        js_data = jsonify({'message': 'updated successfully'})
        return js_data
    except Exception as e:
        print("Err", e)
        js_data = jsonify({'message': 'Something went wrong'})
        return js_data


if __name__ == "__main__":

    print("Main")
    app.debug = True
    app.run(host='0.0.0.0', port=6001)
    # addnewusers()
    # addnewdevices(username="Askar2019",mongo=mongo)
    # populate_newusers(mongo)
    # #one_query()
    # populate_device(mongo)
    # add_newasset(mongo)
