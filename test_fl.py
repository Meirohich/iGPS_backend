import sys
sys.path.insert(1, '/home/mag/Projects/igps_app')
import utils
from flask import Flask, jsonify
from flask_pymongo import PyMongo


app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/sttechdb'
mongo = PyMongo(app)

@app.route('/test_mongodb_connection')
def test_mongodb_connection():
    data = mongo.db.new_users.find_one()
    if data:
        return jsonify({'message': 'MongoDB connection successful', 'data': data})
    else:
        return jsonify({'message': 'MongoDB connection failed'})

@app.route('/')
def index():
      return "Hello world!" 

if __name__ == '__main__':
       app.debug = True
       app.run(host="0.0.0.0", port=6001)
