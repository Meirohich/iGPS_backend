import xml.etree.ElementTree as ET
from flask import Flask
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/sttechdb'
app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'



tree = ET.parse("upFile1650629521.xml")

print(tree)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

lst = list(mongo.db.devices.find({"username":"4368155"},{"messages":False}))

print(lst)

def is_in_list(check_esn, lst):
    
    for el in lst:
        if check_esn == el['esn']:
            return True
        else:
            continue

    return False


# parse message
# prepare the list of globalsys

# if mess['esn'] inside devices with username: globalsys
#   then forward to API
# else:
#    continue

# if message belongs to a list of username globalsys then
#   forward that file to API
# if not then continue

# db.devices.find({username:"4368155"},{messages:false})


