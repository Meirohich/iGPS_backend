import sys
sys.path.insert(1, '/home/mag/Projects/igps_app')
from mongoengine import *
from app.models import *
import requests
import pandas as pd
import time

# connect to db
connect(db="sttechdb", host="127.0.0.1", port=27017)
connect(host='mongodb://127.0.0.1:27017/sttechdb')




class NewUsers(Document):

    id = IntField(primary_key=True)    
    username = StringField()
    email = StringField()
    password = StringField()
    name = StringField()
    mobile = StringField()
    lang = StringField()

class LatestSpotMessages(Document):
    username=StringField()
    feedId=StringField()
    latest_message = DictField()
    messengerId=StringField()

def alreadyExists(username, col):
    if col.objects(username__contains=username).count() > 0:
        return True
    else:
        return False

def get_user_cred(filename):

    print("Inside getUserCred")
    
    #filename = '/home/mag/spottrace_2021_March.csv'  
    #filename = '/home/mag/spottrace_2021_24_March.csv'
    #filename = '/home/mag/spottrace_2021_30_March.csv'
    #filename = '/home/mag/smartone_test.csv'
    dd = pd.read_csv(filename)
    
    dd['FeedID'] = dd['FeedID'].str.strip(" |\n|\r")
    dd['Login'] = dd['Login'].str.strip(" |\n|\r")
    dd['ESNs'] = dd['ESNs'].str.strip(" |\n|\r")

    #dd = dd.drop([10,11,12,13,15,17,47])

    url = "http://127.0.0.1:5001/is_registered"
   
    for username in zip(dd['Login']):

        username = username[0] 

        if pd.isna(username):
            continue
        else:
            url = "http://127.0.0.1:5001/is_registered"
            data = {
                "username": username,                
            }
            
            x = requests.post(url, json = data)
            a = x.json()
            time.sleep(0.2)
     
            print(" --------------- ")
            if a["message"] == False:
                print("User " + str(username) + " is not registered")
                print(dd.loc[dd['Login'] == username, 'Password'].values[0])
                print(dd.loc[dd['Login'] == username,'Login'].values[0])
                print(dd.loc[dd['Login'] == username,'Name'].values[0])
                print(dd.loc[dd['Login'] == username,'Email'].values[0])
                
                data = {
                    "name": dd.loc[dd['Login'] == username,'Name'].values[0], 
                    "username": dd.loc[dd['Login'] == username,'Login'].values[0],
                    "password": dd.loc[dd['Login'] == username, 'Password'].values[0], 
                    "email": dd.loc[dd['Login'] == username,'Email'].values[0],
                    "mobile":dd.loc[dd['Login'] == username,'Mobile'].values[0],
                    "lang":"ru"
                }
                
                print("Data")
                print(data)

                url2 = "http://127.0.0.1:5001/reg"
                
                x = requests.post(url2, json = data)

                print(x.text)
                
                time.sleep(0.2)                                         
            
            else:
                print("User " + str(username) + " is registered")        
                     
                data = {
                    "username": username,
                }
                
                url2 = "http://127.0.0.1:5001/reg_devices"
                
                x = requests.post(url2, json = data)
                print(x.text)        
                time.sleep(0.01)         

                # if ESNs is not empty, then
                #   call reg_smartone API
                #   userid assign 10000
                
                #df['Login'] = df['Login'].str.strip(" |\n|\r")
                

                if pd.isna(dd[dd['Login'] == username]['ESNs'].values[0]) == False:
                    
                    lin = dd[dd['Login'] == username]['ESNs'].values[0]
                    lin = lin.replace(" ","")
                    esn_list = lin.split(";")
                    print(False)

                    for esn in esn_list:
                        
                        print(username)
                        print("space")
                        print(esn)

                        data = {
                            "username": username,
                            "userid": 10000,
                            "esn": esn
                        }
                        
                        #print (data)
                        
                        url="http://127.0.0.1:5001/reg_smartone"
                        x = requests.post(url,json=data)
                        
                        print("response from reg_smartone")
                        print(x.text)
                        
                        time.sleep(0.01)


                

def from_devices_to_latest_messages(filename):

    print("Inside from devices_to_latest")
    
    dd = pd.read_csv(filename)
    
    dd['FeedID'] = dd['FeedID'].str.strip(" |\n|\r")
    dd['Login'] = dd['Login'].str.strip(" |\n|\r")
    dd['ESNs'] = dd['ESNs'].str.strip(" |\n|\r")

    #dd = dd.drop([10,11,12,13,15,17,47])

    url = "http://127.0.0.1:5001/is_registered"
   
    for username in zip(dd['Login']):

        username = username[0] 

        if pd.isna(username):
            continue
        
        else:
        
            url = "http://127.0.0.1:5001/is_registered"
            data = {
                "username": username,                
            }
            
            x = requests.post(url, json = data)
            a = x.json()
            time.sleep(0.002)
            print(username) 
            print(" --------------- ")
            if a["message"] == True:

                if pd.isna(dd[dd['Login'] == username]['ESNs'].values[0]) == False:

                    url = "http://127.0.0.1:5001/dev_to_lat"
                    data = {
                        "username": username,                
                    }
            
                    x = requests.post(url, json = data)
                    a = x.json()
                    print(a)
                    time.sleep(0.2)

  

def create_new_users():
   
    print("function Update coords")
    latest_message_col = LatestSpotMessages.objects().as_pymongo()
   
    print(len(latest_message_col))

    for i in range(len(latest_message_col)):
        username = latest_message_col[i]["username"]
        print("for")
        print(username)

        if alreadyExists(username):
            print("exists continue")
        else:
            url = "http://127.0.0.1:5001/register"
            username = latest_message_col[i]["username"]
            df = get_user_cred(username)

            if df['Login'].empty:
                continue
            else:
                print("Inside else")
                print(df['Имя'][0])
                print(df['Login'][0])
                data = {
                    "name":df["Имя"][0], 
                    "login":df["Login"][0],
                    "password":df["Password"][0], 
                    "email":df["примечание"][0],
                    "mobile":"None" 
                }

                x = requests.post(url, json = data)

                print(x.text)              

#filename = '/home/mag/smartone_test.csv'
filename = '/home/nrblt/igpskz_2021_20_May.csv'
get_user_cred(filename)
from_devices_to_latest_messages(filename)

