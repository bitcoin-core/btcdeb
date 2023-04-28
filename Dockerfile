FROM alpine

RUN apk update && apk upgrade

ENV BUILD_DEPS autoconf file gcc libc-dev make g++ pkgconf re2c git libtool automake build-base gcc

RUN apk add --update --no-cache --virtual .build-deps $BUILD_DEPS

WORKDIR /tmp/btcdeb

COPY . .

RUN ./autogen.sh

RUN ./configure

RUN make clean

RUN make

RUN make install
