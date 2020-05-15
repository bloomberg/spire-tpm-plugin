FROM golang:latest AS go

FROM ubuntu:20.04

RUN addgroup --gid 1000 docker \
    && adduser --uid 1000 --ingroup docker --home /home/docker --shell /bin/sh --disabled-password --gecos "" docker

RUN apt-get update \
    && apt-get install -y \
        curl \
        gcc \
        libtspi-dev \
        make \
        pwgen \
        tpm2-tools \
        xxd

RUN USER=docker \
    && GROUP=docker \
    && curl -SsL https://github.com/boxboat/fixuid/releases/download/v0.4.1/fixuid-0.4.1-linux-amd64.tar.gz | tar -C /usr/local/bin -xzf - \
    && chown root:root /usr/local/bin/fixuid \
    && chmod 4755 /usr/local/bin/fixuid

COPY fixuid.yml /etc/fixuid/config.yml

COPY --from=go /usr/local/go /usr/local/go
ENV PATH=$PATH:/usr/local/go/bin

USER docker:docker
WORKDIR /home/docker/spire-tpm-plugin
CMD ["sh", "-c", "trap : TERM INT; ( while true; do sleep 0.1; done ) & wait"]

RUN mkdir -p /home/docker/go
