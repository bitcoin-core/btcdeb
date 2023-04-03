FROM chibidev/emsdk:alpine as base

#RUN echo 'Acquire::HTTP::Proxy "http://172.17.0.1:3142";' >> /etc/apt/apt.conf.d/01proxy \
# && echo 'Acquire::HTTPS::Proxy "false";' >> /etc/apt/apt.conf.d/01proxy

RUN apk --no-cache --update add \
    autoconf \
    automake \
    bison \
    boost-dev \
    cmake \
    curl \
    g++ \
    gcc \
    git \
    libevent-dev \
    libqrencode-dev \
    libtool \
    linux-headers \
    make \
    miniupnpc-dev \
    patch \
    perl \
    pkgconfig \
    python3 \
    qt5-qtbase-dev \
    qt5-qttools-dev \
    sqlite \
    valgrind \
    vim \
    zeromq-dev

RUN apk update \
    && apk add ${VERBOSE} ${NO_CACHE} \
        alpine-sdk sudo bash-completion \
		git vim curl shadow openssh-client \
		util-linux autoconf

FROM scratch as user
COPY --from=base . .

ARG HOST_UID=${HOST_UID:-4000}
ARG HOST_USER=${HOST_USER:-nodummy}

RUN [ "${HOST_USER}" == "root" ] || \
    (adduser -h /home/${HOST_USER} -D -u ${HOST_UID} ${HOST_USER} \
    && chown -R "${HOST_UID}:${HOST_UID}" /home/${HOST_USER})

RUN for u in $(ls /home); do for g in disk lp floppy audio cdrom dialout video netdev games users; do addgroup $u $g; done;done

ARG PASSWORD=${PASSWORD}
RUN echo ${HOST_USER}:${PASSWORD} | chpasswd
RUN echo root:${PASSWORD} | chpasswd
RUN echo "${HOST_USER} ALL=(ALL) ALL" >> /etc/sudoers
RUN echo "root ALL=(ALL) ALL" >> /etc/sudoers
RUN echo "Set disable_coredump false" >> /etc/sudo.conf

USER ${HOST_USER}
WORKDIR /home/${HOST_USER}

#ENV SSH_PRIVATE_KEY=${SSH_PRIVATE_KEY}
#RUN mkdir -p /home/${HOST_USER}/.ssh &&  chmod 700 /home/${HOST_USER}/.ssh
CMD [ "eval", "`ssh-agent`" ]
#CMD [ "ssh-add", "/home/${HOST_USER}/.ssh/${SSH_PRIVATE_KEY}" ]
#CMD [ "chmod", "600", "/home/${HOST_USER}/.ssh/${SSH_PRIVATE_KEY}" ]
#CMD [ "ssh-add" ]

