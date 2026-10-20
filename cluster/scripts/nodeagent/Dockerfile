# syntax=docker/dockerfile:1.7
#
# Builds ghcr.io/mitstack-eu/mitstack-node-agent, which runs the node report,
# the repository-token refresh and the patch check in the cluster, and on
# mitstack's own cluster OpenBao's init and the GitHub App key's writer.
# Usage: docker build -f scripts/nodeagent/Dockerfile ., from the cluster directory

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache curl gpg openssl python3 util-linux-misc
ADD --checksum=sha256:ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336 \
    https://dl.k8s.io/release/v1.36.3/bin/linux/amd64/kubectl /usr/local/bin/kubectl
RUN chmod 0755 /usr/local/bin/kubectl
COPY --chmod=0755 scripts/nodeagent/host.sh /opt/mitstack/mitstack-host
COPY --chmod=0755 scripts/nodeagent/report.sh /opt/mitstack/mitstack-report
COPY --chmod=0755 scripts/nodeagent/repo-token.sh /opt/mitstack/mitstack-repo-token
COPY --chmod=0755 scripts/nodeagent/openbao.py /opt/mitstack/mitstack-openbao
COPY --chmod=0644 scripts/nodeagent/collect.sh scripts/mitstack-patch-check.sh scripts/mitstack-scan.py scripts/refusal-reason.sh /opt/mitstack/
COPY --chmod=0644 scripts/nodeagent/in-cluster.kubeconfig /opt/mitstack/in-cluster.kubeconfig
ENV PATH=/opt/mitstack:$PATH
