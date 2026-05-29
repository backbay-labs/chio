# ClusterFuzzLite builder image for Chio.
#
# Companion docs in docs/fuzzing/continuous.md (ClusterFuzzLite bridge section).
#
# Mirrors the OSS-Fuzz scaffold under infra/oss-fuzz/
# so the in-tree builder image and the CFLite builder image stay
# behaviourally identical: same base image, same build deps, same
# build.sh shape. Divergence between the two is a process bug.

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        pkg-config \
        libssl-dev \
        perl \
        clang \
        zip \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=3.3.7
ARG OPENSSL_SHA256=4900be54e81c4dfe00bb1a10dad33fd8414833573c40d0e9e3274d4ed32e53a2
RUN cd /tmp \
    && curl -fsSLO "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - \
    && tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz" \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure linux-x86_64 no-shared no-pinshared no-module no-legacy no-tests no-docs no-apps --prefix=/opt/openssl-3 --openssldir=/opt/openssl-3/ssl \
    && make -j"$(nproc)" install_sw \
    && cd /tmp \
    && rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"

ENV OPENSSL_DIR=/opt/openssl-3
ENV OPENSSL_INCLUDE_DIR=/opt/openssl-3/include
ENV OPENSSL_LIB_DIR=/opt/openssl-3/lib64
ENV PKG_CONFIG_PATH=/opt/openssl-3/lib64/pkgconfig

# ClusterFuzzLite mounts the repo into $SRC at runtime; the
# `COPY . $SRC/chio` line below is a no-op in that flow but keeps
# the image self-contained for local `docker build` smoke tests.
COPY . $SRC/chio
WORKDIR $SRC/chio

COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
