import json, os, uuid, base64, redis, time, hmac, hashlib, keyword, re, requests
from bottle import Bottle, request, response
from functools import wraps
from urllib.parse import urlparse
import logging

# Settings
admin_password = os.getenv("ADMIN_PASSWORD", "changeme")
redis_datadir = '/data'
redis_maxmemory = '128mb'
k3u_version = "0.0.7"
salt = "@Id8jKtYn"
default_ttl = 2592000
debug = False

app = Bottle()

# Configure logging
logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
logger = logging.getLogger(__name__)

# The default path renders a hello world JSON message
@app.get('/')
def get_home():
    return dict(msg="This is keiju", release=str(k3u_version), instance=str(cluster_id))

def return_error(message, status):
    response.status = status
    return dict(message=message)

# API names must match this regex
def _valid_identifier_apis(i):
    return re.match("[_A-Za-z][_a-zA-Z0-9]*$", i) and not keyword.iskeyword(i)

# Admin Auth
def validate_admin(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            user = request.auth[0]
            pw = request.auth[1]
        except Exception as e:
            logger.error(f"Auth error: {e}")
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
    return dict(msg="config info")

# List all APIs
@app.route('/config/apis', method='GET')
@validate_admin
def get_apis():
    output = []
    api_list = rc.scan_iter("API:*")
    for api in api_list:
        api_record = json.loads(rc.get(api))
        api_out = {
            "name": api_record["name"],
            "url": api_record["url"],
            "methods": api_record["methods"],
            "auth": api_record["auth"],
            "swagger": api_record["swagger"]
        }
        output.append(api_out)
    return dict(apis=output)

# Create an API
@app.route('/config/apis', method='POST')
@validate_admin
def create_api():
    try:
        api_name = request.forms["name"]
        api_url = request.forms["url"]
    except KeyError:
        response.status = 400
        return dict(info="Need name and URL. Read the documentation?")

    api_methods = request.forms.get("methods", "GET,POST,PUT,DELETE").split(",")
    api_auth = request.forms.get("auth", "none")

    if api_auth not in ['apikey', 'basic', 'none']:
        response.status = 400
        return dict(info="Requested auth is invalid.")

    if not _valid_identifier_apis(api_name):
        response.status = 400
        return dict(info="API name contains invalid characters.")

    if rc.get("API:" + api_name) is not None:
        response.status = 400
        return dict(info="An API with this name exists already.")

    api = {
        "name": api_name,
        "url": api_url,
        "methods": api_methods,
        "auth": api_auth,
        "swagger": "not_implemented_yet"
    }

    rc.set("API:" + api_name, json.dumps(api))
    return dict(api)

# Get one API
@app.route('/config/apis/<id>', method='GET')
@validate_admin
def get_api_details(id):
    api_record = rc.get("API:" + id)
    if api_record is None:
        response.status = 404
        return dict(info="No such API.")

    api_record = json.loads(api_record)
    api_out = {
        "name": api_record["name"],
        "url": api_record["url"],
        "methods": api_record["methods"],
        "auth": api_record["auth"],
        "swagger": api_record["swagger"]
    }
    return dict(api_out)

# Delete an API
@app.route('/config/apis/<id>', method='DELETE')
@validate_admin
def delete_api(id):
    api_record = rc.get("API:" + id)
    if api_record is None:
        response.status = 404
        return dict(info="No such API.")

    rc.delete("API:" + id)
    return dict(info="API deleted")

# Create Basic Auth User
@app.route('/config/basic-auth', method='POST')
@validate_admin
def create_basicauth():
    try:
        username = request.forms["username"]
        password = request.forms["password"]
    except KeyError:
        response.status = 400
        return dict(info="Need username and password. Read the documentation?")

    if not _valid_identifier_apis(username):
        response.status = 400
        return dict(info="Username contains invalid characters.")

    pwhash = _get_password_hash(password)
    rc.set("USER:" + username, pwhash)
    return dict(info="Basic Auth User created/updated.", ttl=str(default_ttl))

# Create API Key
@app.route('/config/apikey', method='POST')
@app.route('/config/apikeys', method='POST')
@validate_admin
def create_apikey():
    apikey = "K3U" + str(uuid.uuid4()).replace("-", "")
    rc.set("KEY:" + apikey, str(time.time()))

    if 'raw' in request.query:
        return apikey
    else:
        return dict(apikey=apikey, ttl=str(default_ttl))

# Change Admin Password
@app.route('/config/password', method='PUT')
@validate_admin
def set_admin_password():
    try:
        new_password = request.forms["password"]
        pwhash = _get_password_hash(new_password)
        rc.set("_ADMIN_", pwhash)
    except KeyError:
        response.status = 400
        return dict(info="Please supply the new password. Check the documentation?")
    return dict(info="admin password updated.")

# API Proxies - Catch all
@app.route("/<api>/<url:re:.*>", method=['GET', 'POST', 'PUT', 'DELETE'])
def apiproxy(api, url):
    request_id = str(uuid.uuid4())
    client_ip = request.environ.get('REMOTE_ADDR')
    client_agent = request.environ.get('HTTP_USER_AGENT', "")
    method = request.method
    headers = request.headers
    body = request.body

    request_headers = {x: y for x, y in headers.items()}

    log_obj = {
        "Request-ID": request_id,
        "Status": "Unknown",
        "Client-Request": {
            "client-ip": client_ip,
            "client-useragent": client_agent,
            "method": method,
            "headers": str(request_headers)
        },
        "Backend-Request": {},
        "Backend-Response": {},
        "Client-Response": {}
    }

    response.headers["X-REQUEST-ID"] = request_id
    request_id_str = "ID:" + request_id + ":"
    if debug:
        logger.debug(f"{request_id_str} Proxy Request for API {api}")

    api_record = rc.get("API:" + api)
    if api_record is None:
        response.status = 404
        if debug:
            logger.debug(f"{request_id_str} Request for invalid API {api}")
        log_obj["Status"] = "NotFound"
        log_obj["Client-Response"]["code"] = "404"
        log_obj["Client-Response"]["info"] = "no such API"
        logger.info(log_obj)
        return dict(info="No such API.")

    api_record = json.loads(api_record)
    api_data = {
        "name": api_record["name"],
        "url": api_record["url"],
        "methods": api_record["methods"],
        "auth": api_record["auth"],
        "host": str(urlparse(api_record["url"]).hostname) + _xstr(urlparse(api_record["url"]).port)
    }

    (request_scheme, request_netloc, request_path, request_query, request_fragment) = request.urlparts

    # Authentication
    if api_data["auth"] == "apikey":
        apikey = request.headers.get("apikey")
        if not apikey or rc.get("KEY:" + str(apikey)) is None:
            log_obj["Status"] = "Unauthorized"
            log_obj["Client-Response"]["code"] = "401"
            log_obj["Client-Response"]["info"] = "API Key needed but not provided"
            logger.info(log_obj)
            response.status = 401
            return

    if api_data["auth"] == "basic":
        try:
            user = request.auth[0]
            pw = request.auth[1]
            uhs = rc.get("USER:" + str(user)).decode("utf-8")
            hs = _get_password_hash(pw)
            if uhs is None or hs != uhs:
                log_obj["Status"] = "Unauthorized"
                log_obj["Client-Response"]["code"] = "401"
                log_obj["Client-Response"]["info"] = "Basic Auth credentials invalid"
                logger.info(log_obj)
                response.status = 401
                return
        except Exception as e:
            log_obj["Status"] = "Unauthorized"
            log_obj["Client-Response"]["code"] = "401"
            log_obj["Client-Response"]["info"] = "Basic Auth credentials missing"
            logger.info(log_obj)
            response.status = 401
            return

    if method not in api_data["methods"]:
        response.status = 405
        if debug:
            logger.debug(f"{request_id_str} Method not allowed for API {api}")
        log_obj["Status"] = "NotAllowed"
        log_obj["Client-Response"]["code"] = "405"
        log_obj["Client-Response"]["info"] = "Method not allowed for API"
        logger.info(log_obj)
        return

    send_path = request_path.replace("/" + api, "", 1)
    url = api_data["url"] + send_path
    querystring = request_query
    send_headers = dict(request_headers)
    send_headers["User-Agent"] = "keiju/" + str(k3u_version)
    send_headers["Host"] = api_data["host"]

    for header in ["Connection", "Content-Length"]:
        send_headers.pop(header, None)

    log_obj["Backend-Request"]["headers"] = str(send_headers)
    log_obj["Backend-Request"]["url"] = str(url)
    log_obj["Backend-Request"]["querystring"] = str(querystring)

    try:
        r = requests.request(method, url, headers=send_headers, params=querystring, data=body, verify=False, timeout=10)
    except requests.RequestException as e:
        if debug:
            logger.debug(f"{request_id_str} Exception while calling backend: {e}")
        log_obj["Status"] = "Error"
        log_obj["Client-Response"]["code"] = "500"
        log_obj["Client-Response"]["info"] = "Error while calling backend"
        logger.info(log_obj)
        response.status = 500
        return

    if debug:
        logger.debug(f"{request_id_str} API URL: {api_data['url']}")
        logger.debug(f"{request_id_str} API Methods: {api_data['methods']}")
        logger.debug(f"{request_id_str} API Auth: {api_data['auth']}")
        logger.debug(f"{request_id_str} Request User Agent: {client_agent}")
        logger.debug(f"{request_id_str} Request IP: {client_ip}")
        logger.debug(f"{request_id_str} Request Method: {method}")
        logger.debug(f"{request_id_str} Request Headers: {request_headers}")
        logger.debug(f"{request_id_str} Request Scheme: {request_scheme}")
        logger.debug(f"{request_id_str} Request Host: {request_netloc}")
        logger.debug(f"{request_id_str} Request Path: {request_path}")
        logger.debug(f"{request_id_str} Request Query: {request_query}")
        logger.debug(f"{request_id_str} Request Fragment: {request_fragment}")
        logger.debug(f"{request_id_str} Send Headers: {send_headers}")
        logger.debug(f"{request_id_str} Send URL: {url}")
        logger.debug(f"{request_id_str} Send Query: {querystring}")
        logger.debug(f"{request_id_str} Backend Response Code: {r.status_code}")
        logger.debug(f"{request_id_str} Backend Response Headers: {r.headers}")
        logger.debug(f"{request_id_str} Backend Response Body: {r.text}")
        logger.debug(f"{request_id_str} Backend Response Time: {r.elapsed.total_seconds()}")

    log_obj["Backend-Response"]["code"] = str(r.status_code)
    log_obj["Backend-Response"]["headers"] = str(r.headers)
    log_obj["Backend-Response"]["elapsed_time"] = str(r.elapsed.total_seconds())

    for k in r.headers:
        response.headers[k] = r.headers[k]

    for header in ["Connection", "Content-Encoding", "Transfer-Encoding", "Vary"]:
        response.headers.pop(header, None)

    response.headers["Via"] = "keiju/" + str(k3u_version)
    response.status = r.status_code
    log_obj["Status"] = "Processed"
    logger.info(log_obj)
    return r.content

# Default 404 handler
@app.error(404)
def error404(error):
    return "Nothing here."

# Default 405 handler
@app.error(405)
def error405(error):
    return "Method not allowed for this endpoint."

def _cluster_init():
    cid = str(uuid.uuid4())
    rc.set("_K3U_ID_", cid[:8])
    return cid[:8]

def _get_password_hash(pw):
    hash_object = hashlib.sha1((pw + salt).encode('utf-8'))
    return hash_object.hexdigest()

def _set_admin_password():
    pwhash = _get_password_hash(admin_password)
    rc.set("_ADMIN_", pwhash)

def _xstr(inp):
    return "" if inp is None else str(inp)

# Initialization
if not all(k in os.environ for k in ("redis_host", "redis_port")):
    exit("ERROR: please set the environment variables for Redis host")

redis_host = os.environ['redis_host']
redis_port = os.environ['redis_port']
redis_password = os.getenv('redis_password', "")

rc = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, db=0)

if "redis_embedded" in os.environ:
    rc.config_set('dir', redis_datadir)
    rc.config_set('maxmemory', redis_maxmemory)

try:
    if rc.get("_ADMIN_") is None:
        _set_admin_password()
except redis.ConnectionError:
    logger.error(f"ERROR: Unable to connect to Redis at {redis_host}:{redis_port}")
    exit(1)

try:
    cluster_id = rc.get("_K3U_ID_").decode("utf-8")
except (redis.ConnectionError, AttributeError):
    cluster_id = _cluster_init()