FROM golang:1.19-alpine

RUN apk add -u --no-cache build-base sqlite

ENV USERNAME=golang

RUN addgroup -g 1000 $USERNAME \
  && adduser -D \
  -s /bin/ash \
  -u 1000 \
  -h /home/$USERNAME \
  -G $USERNAME \
  $USERNAME

USER ${USERNAME}

