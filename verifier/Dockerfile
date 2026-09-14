FROM node:22-slim

WORKDIR /app/verifier

COPY verifier/package.json verifier/package-lock.json ./
RUN npm ci --omit=dev

COPY verifier/src ./src
# The legal PGP key is read from the same file the browser uses.
COPY static/js/public-keys.js /app/static/js/public-keys.js

# Recorded in every proof bundle so a proof can be re-verified with this exact code.
ARG GIT_SHA=unknown
ENV GIT_SHA=$GIT_SHA

RUN mkdir -p /tmp/zkp

CMD ["node", "src/server.js"]
