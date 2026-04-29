# ClusterFuzzLite builder image for Chio (formerly ARC).
#
# Source-of-truth: .planning/trajectory/02-fuzzing-post-pr13.md
# (ClusterFuzzLite implementation section). Companion docs in
# docs/fuzzing/continuous.md (ClusterFuzzLite bridge section).
#
# Mirrors the OSS-Fuzz scaffold under infra/oss-fuzz/ (M02.P2.T5)
# so the in-tree builder image and the CFLite builder image stay
# behaviourally identical: same base image, same build deps, same
# build.sh shape. Divergence between the two is a process bug and
# blocks the M02 P4 close ledger.

FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        clang \
        zip \
    && rm -rf /var/lib/apt/lists/*

# ClusterFuzzLite mounts the repo into $SRC at runtime; the
# `COPY . $SRC/arc` line below is a no-op in that flow but keeps
# the image self-contained for local `docker build` smoke tests.
COPY . $SRC/arc
WORKDIR $SRC/arc

COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
