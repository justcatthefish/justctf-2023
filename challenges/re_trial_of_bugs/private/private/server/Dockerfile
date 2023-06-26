FROM node:20
ENV NODE_ENV=production

RUN groupadd -r rpg && useradd -r -g rpg rpg

WORKDIR /app
ADD ./package.tar.gz /app
COPY ./local_config.json /app
COPY ./config.json /app/assets/static/config.json
RUN ["yarn", "install"]

USER rpg
CMD ["node", "build/server/server.js"]
