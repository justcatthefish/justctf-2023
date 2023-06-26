FROM nginx:latest

COPY ./nginx.conf /etc/nginx/conf.d/default.conf
ADD ./package.tar.gz /client
COPY ./config.json /client/config.json
