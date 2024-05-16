FROM debian:trixie-slim

RUN DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -yqq python3-pyelftools python3-requests git cmake ninja-build build-essential pkg-config libicu-dev libcapstone-dev bash git unzip \
    && rm -rf /var/lib/apt/lists/*
    
RUN mkdir -p /workdir \ 
     && git clone https://github.com/worawit/blutter
WORKDIR /workdir
ENTRYPOINT ["/bin/bash"]
