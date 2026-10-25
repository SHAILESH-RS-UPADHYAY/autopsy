FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY public ./public
COPY brand ./brand
ENV PORT=3000 NODE_ENV=production
EXPOSE 3000
USER node
CMD ["node", "server/index.ts"]
