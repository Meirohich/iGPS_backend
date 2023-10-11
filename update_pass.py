from flask_bcrypt import Bcrypt
from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['MONGO_URI']='mongodb+srv://jstarsik200211:12345@cluster0.bggioa8.mongodb.net/sttechdb'
app.config['SECRET_KEY']='Th1s1ss3cr3t'


mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# blocked
# user_name = "4346522"
# password = "blocked20210913"

user_name = "4369457"
password = "87026337755"

hash_pass = bcrypt.generate_password_hash(password).decode('utf-8')

mongo.db.new_users.update({"username":user_name},{"$set":{"password":hash_pass}})

#list_user_name = ["4346421","4345955","4360475","4361224","4349707","4361146","2690339","miras.shaltayev","4359300","4360921","2690339","4367536","4361276","4367532","4361687"]
#list_user_name = ["4344211","4344655","4344661","4344741", "4344754", "4346222", "4344755", "4344174", "4344429", "4352114", "4352217", "4352034", "4352040", "4352028", "4360474", "4360475", "4349707", "4432487", "4350002", "4361480", "4345988", "4345267", "4346727", "4345185", "4360921", "4360737", "4358881", "4360339", "4361218", "4361145", "4361146", "2690339", "miras.shaltayev", "4361687", "4367532", "4361276", "4367536", "4367535", "4345159", "4357064", "4354012", "4353755", "4353687", "4358846", "4358909", "4352676", "4358910", "4352707", "4358847", "4367744", "4365863", "4367675", "4352189", "4367440", "4367423", "4345707", "4345257", "4346794", "4374355", "4368161","4351139", "4369455", "4367439","4372147","4373995","4368453", "4331925", "4338462", "4346521", "4346660", "4346669",  "4346421", "4346422", "4345955", "4345154",  "Rassul2"]

#list_user_name = ["4360735","4344191","4361164","4345985","4360921","4367536","4367600","4367610","4367626","4360631","4360339","4361145","4346895","4325672","4346727","4345988","4346878","4361154"]

#for user_name in list_user_name:
#    #user_name = "43"
#    password = "87096140"
#
#    hash_pass = bcrypt.generate_password_hash(password).decode('utf-8')
#
#    mongo.db.new_users.update({"username":user_name},{"$set":{"password":hash_pass}})




