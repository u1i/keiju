curl -u admin:changeme -X POST \
  http://localhost:8080/config/apis \
  -d 'name=currency' \
  -d 'auth=basic' \
  -d 'url=http://backend.yoisho.dob.jp/fx'
