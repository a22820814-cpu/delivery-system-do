FROM node:20-bookworm-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /data

ENV NODE_ENV=production
ENV PORT=3000
ENV SQLITE_PATH=/data/delivery-db.sqlite

EXPOSE 3000

CMD ["node", "server.js"]