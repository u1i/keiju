FROM alpine
MAINTAINER uli.hitzel@gmail.com

EXPOSE 8080

RUN apk update
RUN apk add python3
RUN apk add py3-pip
RUN apk update
RUN apk add redis
RUN mkdir /app
RUN mkdir /data
RUN pip3 install cherrypy bottle redis
COPY k3u.sh /app
RUN chmod a+rx /app/k3u.sh
COPY server.py /app/server.py
COPY keiju.py /app/keiju.py
RUN chmod a+r /app/*
USER 1000
CMD ["/app/k3u.sh"]
