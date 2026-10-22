# SPDX-License-Identifier: Apache-2.0
# Fixture for scripts/test-coolify-live-expands.mjs, built by a lab Coolify
# only: records the build arguments it is given (the build's environment,
# without evaluating it again) and prints that record and its runtime
# environment, hex-encoded, to its log. Holds and serves nothing.
FROM busybox:1.37
ARG EXP_PROJECT
ARG TWIN_PROJECT
ARG EXP_ENVIRONMENT
ARG TWIN_ENVIRONMENT
ARG EXP_SERVER
ARG TWIN_SERVER
ARG EXP_TEAM
ARG TWIN_TEAM
ARG EXP_COMMIT
ARG TWIN_COMMIT
ARG LIT_COMMIT
ARG SOURCE_COMMIT
RUN env | grep -E '^(EXP|TWIN|LIT)_|^SOURCE_COMMIT=' | sort | od -An -tx1 | tr -d ' \n' > /build.hex
CMD ["sh", "-c", "echo \"BUILD:$(cat /build.hex)\"; echo \"RUN:$(env | grep -E '^(EXP|TWIN|LIT)_|^SOURCE_COMMIT=' | sort | od -An -tx1 | tr -d ' \\n')\"; exec sleep 2147483647"]
