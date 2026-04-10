FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY server.js ./
EXPOSE 3000
# Run as non-root user (node image ships with a built-in 'node' user)
USER node
CMD ["node", "server.js"]
