FROM node:19-alpine

WORKDIR /app

EXPOSE 3000
EXPOSE 3001

COPY package.json ./
COPY package-lock.json ./

RUN npm install --production

COPY . .

CMD ["npm", "start"]