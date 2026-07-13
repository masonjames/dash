#!/bin/bash

############################################################################
#
#    Agno Docker Image Builder
#
#    Usage: ./scripts/build_image.sh
#
#    Prerequisites:
#      - Docker Buildx installed
#      - Run 'docker buildx create --use' first
#
############################################################################

set -euo pipefail

CURR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS_ROOT="$(dirname "${CURR_DIR}")"
DOCKER_FILE="Dockerfile"
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/masonjames/dash}"
IMAGE_TAG="${IMAGE_TAG:-$(git -C "${OS_ROOT}" rev-parse HEAD)}"

if [[ ! "${IMAGE_TAG}" =~ ^[a-f0-9]{40}$ ]]; then
    echo "IMAGE_TAG must be the full 40-character Git commit SHA" >&2
    exit 2
fi

# Colors
ORANGE='\033[38;5;208m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "    ${ORANGE}▸${NC} ${BOLD}Building Docker image${NC}"
echo -e "    ${DIM}Image: ${IMAGE_NAME}:${IMAGE_TAG}${NC}"
echo -e "    ${DIM}Platforms: linux/amd64, linux/arm64${NC}"
echo ""

echo -e "    ${DIM}> docker buildx build --platform=linux/amd64,linux/arm64 -t ${IMAGE_NAME}:${IMAGE_TAG} -f ${DOCKER_FILE} ${OS_ROOT} --push${NC}"
docker buildx build --platform=linux/amd64,linux/arm64 -t "${IMAGE_NAME}:${IMAGE_TAG}" -f "${DOCKER_FILE}" "${OS_ROOT}" --push

echo ""
echo -e "    ${BOLD}Done.${NC}"
echo ""
