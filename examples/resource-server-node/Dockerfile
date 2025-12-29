FROM node:20-alpine

WORKDIR /app

# No dependencies, but keep the structure so it's easy to extend later.
COPY package.json ./
COPY server.js ./

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Drop privileges
USER node

CMD ["node", "server.js"]
