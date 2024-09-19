FROM debian:trixie-slim

RUN DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -yqq python3-pyelftools python3-requests git cmake ninja-build build-essential pkg-config libicu-dev libcapstone-dev bash git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/cryptax/blutter
ENV TERM=xterm-256color
RUN echo "PS1='\e[92m\u\e[0m@\e[94m\h\e[0m:\e[35m\w\e[0m# '" >> /root/.bashrc

RUN mkdir -p /workdir
WORKDIR /workdir
ENTRYPOINT ["/bin/bash"]
