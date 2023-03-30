FROM node:16.15.1-alpine3.15
#FROM public.ecr.aws/h4m7c9h3/baseimages:node-14.17.6
WORKDIR /usr/src/app

COPY package.json ./
# COPY tsconfig*.json ./
# COPY nest-cli.json ./
RUN npm install --force

COPY ./ ./

RUN npm run build

CMD npm run start
