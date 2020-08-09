. ./keiju.cfg

curl -u admin:$keiju_password -X PUT http://localhost:8080/config/password --data "password=bla"
