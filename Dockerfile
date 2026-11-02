FROM node:20-bookworm-slim
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY lib ./lib
COPY public ./public
COPY lab ./lab
COPY assets ./assets
EXPOSE 8790
ENV PORT=8790
CMD ["node", "server.js"]
