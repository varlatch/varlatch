# SPDX-License-Identifier: Apache-2.0
# The rehearsal's runner (run.sh): the test binary runs as root, as
# varlatch migrate does on a real host, with Docker's CLI and Compose
# (driving the host's daemon through its socket) and Node (the TypeScript
# host CLI). Built locally per run as vl-rh-<run>-runner, removed by that
# exact name when the run ends.
FROM docker@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS docker
FROM node@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
