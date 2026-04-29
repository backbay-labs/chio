# OSS-Fuzz builder image for Chio (formerly ARC).
#
# Source-of-truth: .planning/trajectory/02-fuzzing-post-pr13.md
# (OSS-Fuzz application steps section). Companion docs in
# docs/fuzzing/continuous.md (OSS-Fuzz integration section).

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        clang \
        zip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/bb-connor/arc /src/arc
WORKDIR $SRC/arc

COPY build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
