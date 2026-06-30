# Build stage
FROM node:20.10.0-bookworm-slim AS build

# Set current working directory
WORKDIR /community-server

# Native dependencies need node-gyp during installation
RUN apt-get update && apt-get install -y --no-install-recommends \
  python3 \
  make \
  g++ \
  && rm -rf /var/lib/apt/lists/*

# Copy the dockerfile's context's community server files
COPY . .

# Install and build the Solid community server
RUN npm install --engine-strict=false --no-audit --no-fund && npm run build



# Runtime stage
FROM node:20.10.0-bookworm-slim

# Add contact informations for questions about the container
LABEL maintainer="Solid Community Server Docker Image Maintainer <thomas.dupont@ugent.be>"

# Container config & data dir for volume sharing
RUN mkdir /config /data

# Set current directory
WORKDIR /community-server

# Data directory used by the modified-css startup command
RUN mkdir .data

# Copy runtime files from build stage
COPY --from=build /community-server/package.json .
COPY --from=build /community-server/bin ./bin
COPY --from=build /community-server/config ./config
COPY --from=build /community-server/dist ./dist
COPY --from=build /community-server/node_modules ./node_modules
COPY --from=build /community-server/templates ./templates

# Informs Docker that the container listens on the specified network port at runtime
EXPOSE 3000

# Set command run by the container
ENTRYPOINT [ "node", "bin/server.js" ]

# By default start like `npm run modified-css`
CMD [ "-c", "config/file-vc.json", "-f", ".data" ]
