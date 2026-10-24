# Build context: repo root. Layers the cloud policy files onto the base gateway
# image (packages/toolgate-gateway/Dockerfile), which does not contain /policy.
# Local compose mounts ../policy instead. Terraform's task definition points
# GATEWAY_LOCKFILE_PATH, GATEWAY_POLICY_PATH and GATEWAY_DOWNSTREAMS_PATH at
# /policy/toolgate.lock.json, /policy/agents.yaml and /policy/gateway.cloud.yaml.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY --chown=root:root policy/ /policy/
