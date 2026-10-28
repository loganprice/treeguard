# ruleid: docker-latest-tag
FROM node:latest

# ok: docker-latest-tag
FROM node:18-alpine

# ruleid: docker-add-usage
ADD http://example.com/archive.tar.gz /tmp/archive.tar.gz

# ok: docker-add-usage
COPY package.json ./

# ruleid: docker-sudo-usage
RUN sudo apt-get update && sudo apt-get install -y curl

# ok: docker-sudo-usage
RUN apt-get update && apt-get install -y curl

# ruleid: docker-root-user
USER root

# ok: docker-root-user
USER node
