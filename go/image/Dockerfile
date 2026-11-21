# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: Apache-2.0
#
# The single-container image of a Go installation (ADR-0059 Decision 8;
# internal docs/design/go-step6.md, decision 9, slice 6.10a):
# ghcr.io/varlatch/varlatchd from 0.50.0, the Go varlatchd and varlatch in
# one distroless image.
#
#   /opt/varlatch/varlatchd   the server (the entrypoint)
#   /opt/varlatch/varlatch    the CLI, where the host backup job finds it (O7)
#   /var/lib/varlatch         the data directory, a volume, the image user's
#   /etc/varlatch/varlatchd.conf   the configuration: mounted, read-only
#   /keys                     where the Root KEK and the Backup Encryption Key
#                             are mounted as files (Docker or Coolify secrets),
#                             never environment variables: varlatchd refuses
#                             to start with a key in its environment, and the
#                             CLI here (VARLATCH_IMAGE) refuses to run with
#                             one (go/lib/keyenv)
#
# It runs as uid and gid 65532 (distroless's nonroot). go/image/build.sh
# builds it from the release's own binaries, given as the named build
# context "assets" (varlatchd-<version>-linux-<arch> and
# varlatch-<version>-linux-<arch>, exactly the files SHA256SUMS lists), with
# the repository as the context for the licenses and notices.

FROM --platform=$BUILDPLATFORM busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS dirs
RUN mkdir -p /out/data /out/conf /out/keys

FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION
ARG TARGETARCH
# The SHA-256 of the release's SHA256SUMS, which lists these binaries: set
# by release.yml (empty in a local or pull request build), it binds the
# image to the signed release it was built from.
ARG RELEASE_SUMS=
COPY --from=assets --chmod=0555 varlatchd-${VERSION}-linux-${TARGETARCH} /opt/varlatch/varlatchd
COPY --from=assets --chmod=0555 varlatch-${VERSION}-linux-${TARGETARCH} /opt/varlatch/varlatch
COPY --chmod=0444 LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/varlatch/
COPY --chmod=0444 LICENSES/AGPL-3.0-or-later.txt LICENSES/Apache-2.0.txt /usr/share/doc/varlatch/LICENSES/
# The data directory is the image user's and nobody else's: a volume made
# from it starts that way.
COPY --from=dirs --chown=65532:65532 --chmod=0700 /out/data /var/lib/varlatch
COPY --from=dirs --chmod=0755 /out/conf /etc/varlatch
COPY --from=dirs --chmod=0755 /out/keys /keys
# Varlatch's own code here is AGPL-3.0-or-later (varlatchd) and Apache-2.0
# (varlatch); THIRD-PARTY-NOTICES.md lists everything else.
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later AND Apache-2.0" \
      org.opencontainers.image.source="https://github.com/varlatch/varlatch" \
      org.opencontainers.image.title="varlatchd" \
      org.opencontainers.image.version="${VERSION}" \
      com.varlatch.release.sha256sums="${RELEASE_SUMS}"
ENV PATH=/opt/varlatch:/usr/local/bin:/usr/bin:/bin \
    VARLATCH_IMAGE=varlatchd
USER 65532:65532
VOLUME ["/var/lib/varlatch"]
EXPOSE 8686
ENTRYPOINT ["/opt/varlatch/varlatchd"]
CMD ["serve", "--config", "/etc/varlatch/varlatchd.conf"]
