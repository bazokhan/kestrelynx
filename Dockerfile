# The program that runs inside the update containers: a static binary for each
# platform the main image is published for, cross-compiled once on the build
# host. The main image carries both and places the one that matches its own
# platform into each container; nothing else of the update containers is built
# here (they use the official Node.js and Python images).
FROM --platform=$BUILDPLATFORM golang:1.26 AS worker
WORKDIR /src
COPY go.mod ./
COPY cmd/kestrelynx-worker ./cmd/kestrelynx-worker
COPY internal/worker ./internal/worker
RUN set -eu; \
    mkdir -p /out/libexec; \
    for arch in amd64 arm64; do \
      CGO_ENABLED=0 GOOS=linux GOARCH=${arch} \
        go build -trimpath -ldflags="-s -w" -o /out/libexec/kestrelynx-worker-${arch} ./cmd/kestrelynx-worker; \
      sha256sum /out/libexec/kestrelynx-worker-${arch} | cut -d' ' -f1 > /out/kestrelynx-worker-${arch}.sha256; \
    done

# Build the static kestrelynx binary.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=worker /out/ /worker/
# -tags timetzdata embeds the IANA timezone database in the binary so daily_at is
# interpreted in TZ (e.g. Asia/Tokyo) even on base images without tzdata.
# The sha256 of each work program is linked in; the binary checks the files in
# /usr/local/libexec/kestrelynx against them when it starts and again whenever
# it places one into a container.
RUN CGO_ENABLED=0 go build -trimpath -tags timetzdata \
    -ldflags="-s -w \
      -X github.com/kitsunetrail/kestrelynx/internal/worker.ProgramSHA256Amd64=$(cat /worker/kestrelynx-worker-amd64.sha256) \
      -X github.com/kitsunetrail/kestrelynx/internal/worker.ProgramSHA256Arm64=$(cat /worker/kestrelynx-worker-arm64.sha256)" \
    -o /out/kestrelynx ./cmd/kestrelynx

# Final image is the official Trivy image (Trivy + its DB tooling already on PATH),
# so KestreLynx shells out to a pinned trivy version (ADR-002). It is Alpine-based.
FROM aquasec/trivy:0.71.2
COPY --from=build /out/kestrelynx /usr/local/bin/kestrelynx
COPY --from=worker --chmod=0755 /out/libexec/ /usr/local/libexec/kestrelynx/
# A separate copy, not a symlink or hardlink to /usr/local/bin/kestrelynx:
# the file capability set below is stored as an extended attribute on this
# one file, and only this copy is meant to run with it. The main body's own
# entrypoint (below) never runs this binary.
COPY --from=build /out/kestrelynx /usr/local/bin/kestrelynx-sensor
# setcap runs here, in the same stage the binary finally ships in, rather
# than in an earlier stage whose result is then copied in with COPY
# --from=: a file capability's extended attribute (security.capability) is
# not part of a layer's portable file metadata the way owner/mode/mtime
# are, so a COPY --from= between build stages is not guaranteed to carry it
# over. This Dockerfile therefore never copies an already-capability-bearing
# file across a stage boundary; setcap always runs directly on the copy
# that ships in the final image. libcap is installed only long enough to
# run setcap once, then removed; removing the package does not touch the
# xattr it already wrote to this file.
#
# Effective bits are deliberately not set (+p, not +ep): an exec with an
# effective bit set fails outright (EPERM) if the process's bounding set is
# missing even one of the named capabilities, which would turn a `cap_add`
# typo in the Sensor's compose file into "the container refuses to start"
# instead of a self-check the observer reports in its evidence file. With
# +p only, whichever of these the bounding set actually grants become
# permitted-but-not-effective after exec; the observer raises them itself
# (sandbox.RaiseEffective) and reports any that did not make it.
RUN apk add --no-cache libcap && \
    setcap cap_sys_ptrace,cap_dac_read_search,cap_bpf,cap_perfmon+p /usr/local/bin/kestrelynx-sensor && \
    apk del libcap
# Pre-create the Sensor's default --evidence-dir, owned by the UID/GID the
# Sensor's own compose file runs it as (65532:65532), so that the first time
# it is mounted over by a fresh, empty named volume (docker-compose.sensor.yml's
# own kestrelynx-runtime volume), Docker's own behavior of copying an image
# directory's existing content and ownership into a brand-new volume leaves
# that volume writable by the Sensor immediately — with no init container
# and no chown step anywhere in the Sensor's own compose file, which never
# runs as root at all (see that file's own user: 65532:65532). A volume that
# already has content (a second `docker compose up`, or one reused from a
# previous version) is never touched by this: Docker only copies the
# image's content into a target that is still completely empty at mount
# time. The directory is also world-writable (sticky): on a daemon with
# userns-remap, the copied ownership lands on the remapped UID rather than
# the host UID 65532 the Sensor runs as (userns_mode: host), and the Sensor
# must still be able to create its evidence file there. This relies on
# only the Sensor (read-write) and the main service (read-only) mounting
# this volume: never mount it read-write into any other container, since
# anything that can write here could pre-create or replace the evidence
# file.
RUN mkdir -p /var/lib/kestrelynx-runtime && chown 65532:65532 /var/lib/kestrelynx-runtime && chmod 1777 /var/lib/kestrelynx-runtime
# The base image's entrypoint is trivy; run kestrelynx instead.
ENTRYPOINT ["kestrelynx"]
CMD ["--config", "/etc/kestrelynx/config.yml"]
