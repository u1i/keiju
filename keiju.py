import json, os, uuid, base64, redis, time, hmac, hashlib, keyword, re, requests
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

# API names must match this regex
def _valid_identifier_apis(i):
        return(re.match("[_A-Za-z][_a-zA-Z0-9]*$", i) and not keyword.iskeyword(i))

# Admin Auth
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

@app.get('/config')
@validate_admin
def get_test():
	return(dict(msg="config info"))

# Lisr all APIs
@app.route('/config/apis', method='GET')
@validate_admin
def get_apis():
	output = []
	api_list = rc.scan_iter("API:*")
	for api in api_list:
		api_record = json.loads(rc.get(api))
		api_out = {}
		api_out["name"] = api_record["name"]
		api_out["url"] = api_record["url"]
		api_out["methods"] = api_record["methods"]
		api_out["auth"] = api_record["auth"]
		output.append(api_out)

	return(dict(apis=output))

# Create an API
@app.route('/config/apis', method='POST')
@validate_admin
def create_api():

	try:
		api_name = request.forms["name"]
		api_url = request.forms["url"]
	except:
		response.status = 400
		return dict({"info":"Need name and URL. Read the documentation?"})

	try:
		api_methods = json.loads(request.forms["methods"])
	except:
		api_methods = ['GET', 'POST', 'PUT', 'DELETE']

	try:
		api_auth = request.forms["auth"]

		if api_auth not in ['apikey', 'basic']:
			response.status = 400
			return dict({"info":"Requested auth is invalid."})
	except:
		api_auth = "none"

	if _valid_identifier_apis(str(api_name)) != True:
		response.status = 400
		return dict({"info":"API name contains invalid characters."})

	if rc.get("API:" + api_name) != None:
		response.status = 400
		return dict({"info":"An API with this name exists already."})

	api = {}
	api["name"] = api_name
	api["url"] = api_url
	api["methods"] = api_methods
	api["auth"] = api_auth

	rc.set("API:" + api_name, json.dumps(api))

	return(dict(name=api_name, url=api_url, methods=str(api_methods), auth=api_auth))

# Get one API
@app.route('/config/apis/<id>', method='GET')
@validate_admin
def get_api_details(id):

	try:
		api_record = json.loads(rc.get("API:" + id))
	except:
		api_record = None

	if api_record == None:
		response.status = 404
		return dict({"info":"No such API."})

	api_out = {}
	api_out["name"] = api_record["name"]
	api_out["url"] = api_record["url"]
	api_out["methods"] = api_record["methods"]
	api_out["auth"] = api_record["auth"]

	return(dict(api_out))

# Delete an API
@app.route('/config/apis/<id>', method='DELETE')
@validate_admin
def delete_api(id):

	try:
		api_record = json.loads(rc.get("API:" + id))
	except:
		api_record = None

	if api_record == None:
		response.status = 404
		return dict({"info":"No such API."})

	rc.delete("API:" + id)
	return(dict(info="API deleted"))

# Change Admin Password
@app.route('/config/password', method='PUT')
@validate_admin
def set_admin_password():

	try:
		new_password = request.forms["password"]
		pwhash = _get_password_hash(new_password)
		rc.set("_ADMIN_", pwhash)

	except:
		response.status = 400
		return dict({"info":"Please supply the new password. Check the documentation?"})

	return(dict(info="admin password updated."))

# API Proxies - Catch all
@app.get("/<api>/<url:re:.*>", method='GET')
@app.get("/<api>/<url:re:.*>", method='POST')
@app.get("/<api>/<url:re:.*>", method='PUT')
@app.get("/<api>/<url:re:.*>", method='DELETE')
def apiproxy(api, url):

	try:
		api_record = json.loads(rc.get("API:" + api))
	except:
		api_record = None

	if api_record == None:
		response.status = 404
		return dict({"info":"No such API."})

	api_out = {}
	api_out["name"] = api_record["name"]
	api_out["url"] = api_record["url"]
	api_out["methods"] = api_record["methods"]
	api_out["auth"] = api_record["auth"]

	method = request.method
	headers = request.headers
	headers_str = ', '.join("{!s}={!r}".format(key,val) for (key,val) in headers.items())

	stuff = request.urlparts

	return("Triggering API '" + str(api) + "' with path " + str(url) + " METHOD: " + method + " HEADERS: " + str(headers_str) + " " + str(stuff))

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
