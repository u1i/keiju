curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=atm' \
  -d 'url=http://backend.yoisho.dob.jp/banking/v2' \
  -d 'auth=basic' \
  -d 'methods=GET,POST'
