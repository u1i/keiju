![](./resources/keiju-02-small.png)

# Keiju – Minimalist API Gateway

* Simplicity wins over Feature Completeness
* Supports API Keys & Basic Auth
* Detailed Request/Response Logging in JSON on STDOUT
* Control & Configure via API Calls
* Runs on Docker, k8s, knative, OpenShift, Google Cloud Run etc.
* Stateful (embedded Redis) by default, or use external Redis

![](./resources/k3u.png)


## Run Keiju with Docker

`docker run -d -p 8080:8080 u1ih/keiju:latest`

## Example 1: Register Proxy & Consume an API (Passthrough)

We're using an API endpoint from the [Yoisho Open Banking Project](http://yoisho.dob.jp/):

```
curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=exchange' \
  -d 'url=http://backend.yoisho.dob.jp/fx'
```

Response:

> {"name": "exchange", "url": "http://backend.yoisho.dob.jp/fx", "methods": ["GET", "POST", "PUT", "DELETE"], "auth": "none", "swagger": "not\_implemented\_yet"}

We didn't explicitly set the allowed methods or authentication, so the default values (all methods, no authentication) are used.

Now we consume the 'protected' API:

`curl "http://localhost:8080/exchange/currency?currency=USD"`

> {"sell": "489.174", "timestamp": "2019-11-03 01:09:43.767149", "buy": "389.112"}

## Example 2: Basic Authentication

### Register API Proxy

```
curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=currency' \
  -d 'auth=basic' \
  -d 'url=http://backend.yoisho.dob.jp/fx'
```

### Create User

```
curl -X POST -u admin:changeme \
http://localhost:8080/config/basic-auth \
-d 'username=uli' -d 'password=bla'
```

### Consume API with Basic Auth

```
curl -u uli:bla \
"http://localhost:8080/currency/currency?currency=USD"
```
> {"sell": "489.186", "timestamp": "2019-11-03 16:28:06.809565", "buy": "389.197"}

## Example 3: API Keys

### Register API Proxy

```
curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=currency' \
  -d 'auth=apikey' \
  -d 'url=http://backend.yoisho.dob.jp/fx'
```

### Create API Key

```
curl -X POST -u admin:changeme \
http://localhost:8080/config/apikeys
```

> {"apikey": "K3Uc18cda3befa640c5acd8045690cd2811", "ttl": "2592000"}


### Consume API with API Key

```
curl -H "apikey:K3Uc18cda3befa640c5acd8045690cd2811" \
"http://localhost:8080/currency/currency?currency=USD"
```
> {"sell": "489.115", "timestamp": "2019-11-03 16:32:11.269691", "buy": "389.112"}


## Example 4: Only Allow Certain HTTP Methods for API

Simply add 'methods' to the list of parameters:

```
curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=atm' \
  -d 'url=http://backend.yoisho.dob.jp/banking/v2' \
  -d 'methods=GET,POST'
```

## Admin Stuff & More Details

### List all API Proxies

`curl -u admin:changeme http://localhost:8080/config/apis`

### Delete an API Proxy

`curl -u admin:changeme -X DELETE http://localhost:8080/config/apis/currency`

### Change Admin Password

`curl -u admin:changeme -X PUT http://localhost:8080/config/password --data "password=newpassword"`

### Get 'raw' API Key, not in JSON

```
curl -X POST -u admin:changeme \
"http://localhost:8080/config/apikeys?raw"
```

### Stateless Container

Connect to external Redis by setting the environment variables redis_host, redis_port, redis_password (optional).

### So an API Key or Basic Auth gets you access to all APIs? No 'applications'?

Yes. Simplicity.

### How does Logging work?

`docker logs CONTAINER_ID`

### What about HTTPS ?

I suggest to have nginx, haproxy, k8s etc. take care of that. Try running it on Google Cloud Run!

### keiju?

A japanese name. But it also means fairy in Finnish.

### Coming soon(ish?)

* Rate-Limits
* TTL for API Keys
* Swagger Passthrough/Parse

### Image on Docker Hub

[https://hub.docker.com/r/u1ih/keiju](https://hub.docker.com/r/u1ih/keiju)

### Logging to STDOUT – JSON Format

`{'Request-ID': 'a0bc6d5c-70d4-42fa-9ad2-b1604cb31a16', 'Status': 'Unauthorized', 'Client-Request': {'client-ip': '127.0.0.1', 'client-useragent': 'curl/7.64.1', 'method': 'GET', 'headers': "{'Host': 'localhost:8080', 'User-Agent': 'curl/7.64.1', 'Accept': '*/*', 'Apikey': 'K3Uc18cda3befa640c5acd8045690cd2811'}"}, 'Backend-Request': {}, 'Backend-Response': {}, 'Client-Response': {'code': '401', 'info': 'API Key needed but not provided'}}`

`{'Request-ID': '4fad9881-e50b-43c8-b7e9-08349cead147', 'Status': 'Processed', 'Client-Request': {'client-ip': '127.0.0.1', 'client-useragent': 'curl/7.64.1', 'method': 'GET', 'headers': "{'Host': 'localhost:8080', 'User-Agent': 'curl/7.64.1', 'Accept': '*/*', 'Apikey': 'K3U63b4dcd1e93b494fa19bd9264832c840'}"}, 'Backend-Request': {'headers': "{'Host': 'backend.yoisho.dob.jp', 'User-Agent': 'keiju/0.0.6', 'Accept': '*/*', 'Apikey': 'K3U63b4dcd1e93b494fa19bd9264832c840'}", 'url': 'http://backend.yoisho.dob.jp/fx/currency', 'querystring': 'currency=USD'}, 'Backend-Response': {'code': '200', 'headers': "{'Date': 'Wed, 10 Jun 2020 02:49:14 GMT', 'Content-Type': 'application/json', 'Content-Length': '80', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD', 'X-Clacks-Overhead': 'GNU Terry Pratchett', 'Server': 'PythonAnywhere'}", 'elapsed_time': '0.616486'}, 'Client-Response': {}}`

`{'Request-ID': 'e23a5726-b52c-4d5b-a9c5-4f5de4817bce', 'Status': 'Processed', 'Client-Request': {'client-ip': '127.0.0.1', 'client-useragent': 'curl/7.64.1', 'method': 'GET', 'headers': "{'Host': 'localhost:8080', 'User-Agent': 'curl/7.64.1', 'Accept': '*/*', 'Apikey': 'K3U63b4dcd1e93b494fa19bd9264832c840'}"}, 'Backend-Request': {'headers': "{'Host': 'backend.yoisho.dob.jp', 'User-Agent': 'keiju/0.0.6', 'Accept': '*/*', 'Apikey': 'K3U63b4dcd1e93b494fa19bd9264832c840'}", 'url': 'http://backend.yoisho.dob.jp/fx/currency', 'querystring': 'currency=USD'}, 'Backend-Response': {'code': '200', 'headers': "{'Date': 'Wed, 10 Jun 2020 02:49:17 GMT', 'Content-Type': 'application/json', 'Content-Length': '80', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD', 'X-Clacks-Overhead': 'GNU Terry Pratchett', 'Server': 'PythonAnywhere'}", 'elapsed_time': '0.498662'}, 'Client-Response': {}}`