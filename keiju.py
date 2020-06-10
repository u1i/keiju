import json, os, uuid, base64, redis, time, hmac, hashlib, keyword, re, requests
from bottle import Bottle, request, response
from functools import wraps
from urllib.parse import urlparse

# Settings
admin_password = "changeme"
redis_datadir = '/data'
redis_maxmemory = '128mb'
k3u_version = "0.0.6"
salt = "@Id8jKtYn"
default_ttl = 2592000
debug = False

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

# List all APIs
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
		api_out["swagger"] = api_record["swagger"]
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
		#api_methods = json.loads(request.forms["methods"])
		api_methods = request.forms["methods"].split(",")
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
	api["swagger"] = "not_implemented_yet"

	rc.set("API:" + api_name, json.dumps(api))

	#return(dict(name=api_name, url=api_url, methods=str(api_methods), auth=api_auth))
	return(dict(api))

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
	api_out["swagger"] = api_record["swagger"]

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

# Create Basic Auth User
@app.route('/config/basic-auth', method='POST')
@validate_admin
def create_basicauth():

	try:
		username = request.forms["username"]
		password = request.forms["password"]
	except:
		response.status = 400
		return dict({"info":"Need username and password. Read the documentation?"})

	if _valid_identifier_apis(str(username)) != True:
		response.status = 400
		return dict({"info":"Username contains invalid characters."})

	pwhash = _get_password_hash(password)
	rc.set("USER:" + username, pwhash)
	return(dict(info="Basic Auth User created/updated.", ttl=str(default_ttl)))

# Create API Key
@app.route('/config/apikey', method='POST')
@app.route('/config/apikeys', method='POST')
@validate_admin
def create_apikey():

	apikey = "K3U" + str(uuid.uuid4()).replace("-", "")
	rc.set("KEY:" + apikey, str(time.time()))

	if 'raw' in request.query:
		return(apikey)
	else:
		return(dict(apikey=apikey, ttl=str(default_ttl)))

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

	# Generate a Request ID
	request_id = str(uuid.uuid4())

	# Get Info abouy the Request from the Client
	client_ip = request.environ.get('REMOTE_ADDR')
	try:
		client_agent = request.environ.get('HTTP_USER_AGENT')
	except:
		client_agent = ""

	method = request.method
	headers = request.headers
	body = request.body

	request_headers = {}

	for (x,y) in headers.items():
		request_headers[x] = y

	log_obj = {}

	log_obj["Request-ID"] = request_id
	log_obj["Status"] = "Unknown"
	log_obj["Client-Request"] = {}
	log_obj["Client-Request"]["client-ip"] = client_ip
	log_obj["Client-Request"]["client-useragent"] = client_agent
	log_obj["Client-Request"]["method"] = method
	log_obj["Client-Request"]["headers"] = str(request_headers)

	log_obj["Backend-Request"] = {}
	log_obj["Backend-Response"] = {}
	log_obj["Client-Response"] = {}

	# Return the Quest ID
	response.headers["X-REQUEST-ID"] = str(request_id)
	request_id_str = "ID:" + request_id + ":"
	if debug:
		print (request_id_str + "Proxy Request for API " + api)

	# Get Info about this API Proxy
	try:
		api_record = json.loads(rc.get("API:" + api))
	except:
		api_record = None

	if api_record == None:
		response.status = 404
		if debug:
			print (request_id_str + "Request for invalid API " + api)

		log_obj["Status"] = "NotFound"
		log_obj["Client-Response"]["code"] = "404"
		log_obj["Client-Response"]["info"] = "no such API"
		print(log_obj)
		return dict({"info":"No such API."})

	api_data = {}
	api_data["name"] = api_record["name"]
	api_data["url"] = api_record["url"]
	api_data["methods"] = api_record["methods"]
	api_data["auth"] = api_record["auth"]
	api_data["host"] = str(urlparse(api_data["url"]).hostname) + _xstr(urlparse(api_data["url"]).port)

	(request_scheme, request_netloc, request_path, request_query, request_fragment) = request.urlparts

	# Authentication
	# API Key
	if api_data["auth"]  == "apikey":
		try:
			apikey = request.headers["apikey"]
			chk = rc.get("KEY:" + str(apikey))

			if chk == "" or chk == None:
				log_obj["Status"] = "Unauthorized"
				log_obj["Client-Response"]["code"] = "401"
				log_obj["Client-Response"]["info"] = "API Key needed but not provided"
				print(log_obj)

				response.status = 401
				return
		except:
			log_obj["Status"] = "Unauthorized"
			log_obj["Client-Response"]["code"] = "401"
			log_obj["Client-Response"]["info"] = "API Key invalid"
			print(log_obj)

			response.status = 401
			return

	# Basic Auth
	if api_data["auth"]  == "basic":
		try:
			user = request.auth[0]
			pw = request.auth[1]

			uhs = rc.get("USER:" + str(user)).decode("utf-8")
			hs = _get_password_hash(pw)

			if uhs == "" or uhs == None or hs != uhs:

				print (uhs)
				print (hs)
				log_obj["Status"] = "Unauthorized"
				log_obj["Client-Response"]["code"] = "401"
				log_obj["Client-Response"]["info"] = "Basic Auth credentials invalid"
				print(log_obj)

				response.status = 401
				return
		except:
			log_obj["Status"] = "Unauthorized"
			log_obj["Client-Response"]["code"] = "401"
			log_obj["Client-Response"]["info"] = "Basic Auth credentials missing"
			print(log_obj)

			response.status = 401
			return

	# Check if the method is allowed for this API
	if method not in api_data["methods"]:
		response.status = 405

		if debug:
			print (request_id_str + " Method not allowed for API " + api)

		log_obj["Status"] = "NotAllowed"

		log_obj["Client-Response"]["code"] = "405"
		log_obj["Client-Response"]["info"] = "Method not allowed for API"
		print(log_obj)

		return

	# Prepare the Request to the Backend

	# strip the API name from the request path
	send_path = request_path.replace("/" + api, "", 1)

	url = api_data["url"] + send_path

	querystring = request_query

	headers = dict(request_headers)
	send_headers = dict(headers)

	send_headers["User-Agent"] = "keiju/" + str(k3u_version)
	send_headers["Host"] = api_data["host"]

	try:
		del send_headers["Connection"]
	except:
		pass

	try:
		del send_headers["Content-Length"]
	except:
		pass

	# Send the Request to the Backend

	log_obj["Backend-Request"]["headers"] = str(send_headers)
	log_obj["Backend-Request"]["url"] = str(url)
	log_obj["Backend-Request"]["querystring"] = str(querystring)

	try:
		r = requests.request(method, url, headers=send_headers, params=querystring, \
		data=body, verify=False, timeout=10)
	except:
		if debug:
			print (request_id_str + "Exception while calling backend")
			log_obj["Status"] = "Error"

			log_obj["Client-Response"]["code"] = "500"
			log_obj["Client-Response"]["info"] = "Error while calling backend"
			print(log_obj)

		response.status = 500
		return

	if debug:
		print (request_id_str + "API URL: " + str(api_data["url"]))
		print (request_id_str + "API Methods: " + str(api_data["methods"]))
		print (request_id_str + "API Auth: " + str(api_data["auth"]))
		print (request_id_str + "Request User Agent: " + str(client_agent))
		print (request_id_str + "Request IP: " + str(client_ip))
		print (request_id_str + "Request Method: " + str(method))
		print (request_id_str + "Request Headers: " + str(request_headers))
		print (request_id_str + "Request Scheme: " + str(request_scheme))
		print (request_id_str + "Request Host: " + str(request_netloc))
		print (request_id_str + "Request Path: " + str(request_path))
		print (request_id_str + "Request Query: " + str(request_query))
		print (request_id_str + "Request Fragment: " + str(request_fragment))

		print (request_id_str + "Send Headers: " + str(send_headers))
		print (request_id_str + "Send URL: " + str(url))
		print (request_id_str + "Send Query: " + str(querystring))

		print (request_id_str + "Backend Response Code: " + str(r.status_code))
		print (request_id_str + "Backend Response Headers: " + str(r.headers))
		print (request_id_str + "Backend Response Body: " + str(r.text))
		print (request_id_str + "Backend Response Time: " + str(r.elapsed.total_seconds()))


	log_obj["Backend-Response"]["code"] = str(r.status_code)
	log_obj["Backend-Response"]["headers"] = str(r.headers)
	log_obj["Backend-Response"]["code"] = str(r.status_code)
	log_obj["Backend-Response"]["elapsed_time"] = str(r.elapsed.total_seconds())


	# Copy Headers from the Backend Response to what we send back to the Client
	for k in r.headers:
		response.headers[k] = r.headers[k]

	try:
		del response.headers["Connection"]
	except:
		pass

	try:
		del response.headers["Content-Encoding"]
	except:
		pass

	try:
		del response.headers["Transfer-Encoding"]
	except:
		pass

	try:
		del response.headers["Vary"]
	except:
		pass

	response.headers["Via"] = "keiju/" + str(k3u_version)

	response.status = r.status_code
	log_obj["Status"] = "Processed"

	print(log_obj)
	#return(r.text)
	return(r.content)

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

def _xstr(inp):
	if inp == None:
		return ""
	else:
		return str(inp)

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

try:
	cluster_id = rc.get("_K3U_ID_").decode("utf-8")
except:
	cluster_id = None

if cluster_id == None:
	cluster_id = _cluster_init()
