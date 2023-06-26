FROM node:18-alpine

COPY ./src/ /app/

RUN apk update && apk upgrade
RUN apk add chromium 

WORKDIR /app
RUN echo "justCTF{M4nY_L4y3rS_M4nY_f4ilur3s_ae5bda97-8543-4a4b-84bf-22c6a0df6bdf}" > flag.txt

RUN npm install
EXPOSE 3000
CMD ["npm", "run", "start"]
