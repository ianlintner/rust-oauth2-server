#!/usr/bin/env bash
# Decide whether the CI docker job may publish images to a registry.
#
# Usage: docker_publish_mode.sh EVENT_NAME GITHUB_REF
# Prints `publish=true|false` (appended to $GITHUB_OUTPUT when set).
#
# Registry publication is allowed ONLY for a tag push. Pushes to main/develop
# (including squash merges), pull requests and everything else build the image
# locally and never log in to or push to GHCR/Docker Hub. Official releases are
# cut through the owner-gated release.yml workflow, which creates the tag.
set -euo pipefail

event="${1:?event name required}"
ref="${2:?git ref required}"

publish=false
if [[ "$event" == "push" && "$ref" == refs/tags/* ]]; then
  publish=true
fi

echo "publish=${publish}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "publish=${publish}" >> "$GITHUB_OUTPUT"
fi
