. ./keiju.cfg

curl -u admin:$keiju_password -X POST \
  $keiju/config/apis \
  -d 'name=atm' \
  -d 'url=http://backend.yoisho.dob.jp/banking/v2' \
  -d 'auth=basic' \
  -d 'methods=GET,POST'
