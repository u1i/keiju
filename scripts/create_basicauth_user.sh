. ./keiju.cfg

curl -X POST -u admin:$keiju_password \
-d 'username=uli' \
-d 'password=bla' \
$keiju/config/basic-auth
