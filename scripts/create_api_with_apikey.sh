. ./keiju.cfg

curl -u admin:$keiju_password -X POST \
  $keiju/config/apis \
  -d 'name=currency' \
  -d 'auth=apikey' \
  -d 'url=http://backend.yoisho.dob.jp/fx'
