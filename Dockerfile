#To build: docker build -t pangine/disasm-gt-generator .
FROM pangine/msvc-wine

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    git \
    llvm-8 \
    pkg-config \
    sqlite3 \
    wget

WORKDIR /root/
RUN wget --progress=bar:force:noscroll https://capnproto.org/capnproto-c++-0.8.0.tar.gz && \
    tar zxf capnproto-c++-0.8.0.tar.gz && \
    rm capnproto-c++-0.8.0.tar.gz && \
    cd capnproto-c++-0.8.0 && \
    ./configure && \
    make -j $(nproc --ignore $nprocIgnore) check && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf capnproto-c++-0.8.0

RUN wget --progress=bar:force:noscroll https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.14.4.linux-amd64.tar.gz && \
    rm go1.14.4.linux-amd64.tar.gz

# Change to a non-root user
ARG UID=1001
ARG USER=ubuntu
ARG USER_HOME=/home/${USER}
RUN useradd -m -d ${USER_HOME} -u ${UID} ${USER}
USER ${USER}
WORKDIR ${USER_HOME}

# Install llvmmc-resolver
RUN mkdir .ssh bin
RUN ssh-keyscan github.com >> ${USER_HOME}/.ssh/known_hosts && \
    git clone https://github.com/pangine/llvmmc-resolver && \
    cd llvmmc-resolver && \
    /usr/bin/cmake -Bbuild . && \
    cd build && \
    make -j $(nproc --ignore $nprocIgnore) && \
    mv resolver ${USER_HOME}/bin && \
    cd ../.. && \
    rm -rf llvmmc-resolver

ENV GOPATH="${USER_HOME}/go"
ENV PATH="${USER_HOME}/bin:${USER_HOME}/go/bin:/usr/local/go/bin:${PATH}"

# Install this package inside container
RUN git config --global url.git@gitlab.com:.insteadOf https://gitlab.com/ && \
    go get -u -t zombiezen.com/go/capnproto2/... && \
    go get github.com/mattn/go-sqlite3 && \
    go get -u github.com/pangine/disasm-gt-generator/... && \
    echo "[2020-11-12]"
