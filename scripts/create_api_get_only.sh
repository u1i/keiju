. ./keiju.cfg

curl -u admin:$keiju_password -X POST \
  $keiju/config/apis \
  -d 'name=currency' \
  -d 'url=http://backend.yoisho.dob.jp/fx' \
  -d 'auth=basic' \
  -d 'methods=GET'
