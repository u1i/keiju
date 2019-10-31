import json, os, uuid, base64, redis, time, hmac, hashlib, keyword, re
from bottle import Bottle, request, response
from functools import wraps

# Settings
admin_password = "changeme"
redis_datadir = '/data' # this is currently also set in b9y.sh
redis_maxmemory = '128mb'
k3u_version = "0.0.1"
salt = "@Id8jKtYn"

app = Bottle()

# The default path renders a hello world JSON message
@app.get('/')
def get_home():
	return(dict(msg="This is keiju ", release=str(k3u_version),\
	instance=str(cluster_id)))

def return_error(message, status):
    response.status = status
    return dict({"message":message})

def validate_admin(function):
	@wraps(function)
	def wrapper(*args, **kwargs):

		try:
			user = request.auth[0]
			pw = request.auth[1]

		except:
			return return_error('Credentials missing. Check documentation?', 401)

		stored_password = rc.get("_ADMIN_").decode("utf-8")

		if str(_get_password_hash(pw)) == str(stored_password):
			return function(*args, **kwargs)
		else:
			return return_error('Invalid admin credentials.', 401)

	return wrapper

# user = request.auth[0]
# pw = request.auth[1]
# return return_error('Credentials missing. Check docu?', 401)

@app.get('/test')
@validate_admin
def get_test():
	return(dict(msg="yo!"))

# Change Admin Password
@app.route('/config/password', method='PUT')
def set_admin_password():

	try:
		new_password = request.forms["password"]
	except:
		response.status = 400
		return dict({"info":"Please supply the new password. Check the documentation?"})

#	# Read record for admin user
#	admin_record = json.loads(rc.get("USER:0"))
#	admin_record["hash"] = _get_password_hash(new_password)
#	rc.set("USER:0", json.dumps(admin_record, ensure_ascii=False))

	return(dict(info="updated the admin password"))

# Default 404 handler
@app.error(404)
def error404(error):
    #return 'Nothing here, sorry'
	return("Nothing here.")

# Default 405 handler
@app.error(405)
def error405(error):
    #return 'Nothing here, sorry'
	return("Method not allowed for this endpoint.")

def _cluster_init():
	cid = str(uuid.uuid4())
	rc.set("_K3U_ID_", cid[:8])

	return(cid[:8])

def _get_password_hash(pw):
	hash_object = hashlib.sha1((pw+salt).encode('utf-8'))
	return(hash_object.hexdigest())

def _set_admin_password():
	pwhash = _get_password_hash(admin_password)

	rc.set("_ADMIN_", pwhash)

	return

# Initialization
# We need a Redis connection
if not "redis_host" in os.environ or not "redis_port" in os.environ:
	exit("ERROR: please set the environment variables for Redis host")

# Connect to the Redis backend
redis_host = os.environ['redis_host']
redis_port = os.environ['redis_port']

if "redis_password" in os.environ:
	redis_password = os.environ['redis_password']
else:
	redis_password = ""

rc = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, db=0)

# Configure local Redis
if "redis_embedded" in os.environ:
	rc.config_set('dir', redis_datadir)
	rc.config_set('maxmemory', redis_maxmemory)

# Create record for admin user if it doesn't exist
try:
	if rc.get("_ADMIN_") == None:
		_set_admin_password()
except:
	print ("ERROR: Unable to connect to Redis at " + str(redis_host) + ":" + redis_port)
	exit(1)

# Read unique ID for this instance / cluster or initialize if it doesn't exist
cluster_id = rc.get("_K3U_ID_")

if cluster_id == None:
	cluster_id = _cluster_init()
