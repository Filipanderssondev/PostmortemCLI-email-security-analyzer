#!/bin/bash
# ~/.postmortemcli/setup.sh
# Usage: postmortemcli-update <version>
# Example: postmortemcli-update v0.2.5-beta
#
# Automates the full update lifecycle for PostmortemCLI in a restricted
# enterprise environment with a private container registry.
#
# Requirements on image server: buildah, trivy, SSH access
# Requirements on local machine: podman, ssh, Python 3.10+

set -e

# ── Load config ──────────────────────────────────────────────────────────────
if [ -f ~/.postmortemcli/.env ]; then
    source ~/.postmortemcli/.env
    echo "  → Loaded config from ~/.postmortemcli/.env"
else
    echo ""
    echo "  [ERROR] ~/.postmortemcli/.env not found."
    echo "          Copy .env.example to ~/.postmortemcli/.env and fill in your values."
    echo ""
    exit 1
fi

VERSION=${1:-latest}

DOCKERHUB_IMAGE="docker.io/filipanderssondev/postmortemcli:$VERSION"
PRIVATE_IMAGE="$PRIVATE_REGISTRY/$PROJECT_NAMESPACE:$VERSION"

echo ""
echo "══════════════════════════════════════════════"
echo "  PostmortemCLI – Image Update Tool"
echo "══════════════════════════════════════════════"
echo "  Version  : $VERSION"
echo "  Source   : $DOCKERHUB_IMAGE"
echo "  Target   : $PRIVATE_IMAGE"
echo "  Server   : $IMAGE_SERVER"
echo "══════════════════════════════════════════════"
echo ""

# ── Step 0: Clean up existing images ─────────────────────────────────────────
echo "[ 0 / 5 ]  Cleaning up existing images"

echo "  → Stopping any running postmortemcli containers (local)..."
podman ps -q --filter ancestor=postmortemcli 2>/dev/null | xargs -r podman stop 2>/dev/null || true

echo "  → Removing all local postmortemcli images..."
podman images --format "{{.ID}} {{.Repository}}" | grep -i postmortemcli | awk '{print $1}' | xargs -r podman rmi -f 2>/dev/null || true
podman images --format "{{.ID}} {{.Repository}}" | grep -i "$PRIVATE_REGISTRY" | awk '{print $1}' | xargs -r podman rmi -f 2>/dev/null || true

echo "  → Removing postmortemcli images on image server..."
ssh $IMAGE_SERVER "buildah images --format '{{.Name}} {{.ID}}' | grep -i postmortemcli | awk '{print \$2}' | xargs -r buildah rmi -f 2>/dev/null || true"

echo "  → Cleanup complete."
echo ""

# ── Step 1: Trivy security scan ───────────────────────────────────────────────
echo "[ 1 / 5 ]  Security scan"
echo "  → Connecting to $IMAGE_SERVER..."
echo "  → Running Trivy image scan on $DOCKERHUB_IMAGE"
echo "  → Checking for CRITICAL and HIGH vulnerabilities..."
echo ""

ssh $IMAGE_SERVER "trivy image --severity CRITICAL,HIGH --exit-code 0 $DOCKERHUB_IMAGE"

echo ""
echo "──────────────────────────────────────────────"
echo "  Trivy scan complete."
echo "──────────────────────────────────────────────"
echo ""
read -p "  Proceed with pull? (y/n): " CONFIRM_PULL
echo ""

if [[ "$CONFIRM_PULL" != "y" && "$CONFIRM_PULL" != "Y" ]]; then
    echo "  Aborted by user. No changes made."
    echo ""
    exit 0
fi

# ── Step 2: Pull image ────────────────────────────────────────────────────────
echo "[ 2 / 5 ]  Pull image"
echo "  → Pulling $DOCKERHUB_IMAGE from Docker Hub..."
echo ""

ssh $IMAGE_SERVER "buildah pull $DOCKERHUB_IMAGE"

echo ""
echo "  → Pull complete."
echo ""

# ── Step 3: Retag ─────────────────────────────────────────────────────────────
echo "[ 3 / 5 ]  Retag image"
echo "  → Retagging for private registry..."
echo "  → $DOCKERHUB_IMAGE"
echo "       ↓"
echo "  → $PRIVATE_IMAGE"
echo ""

ssh $IMAGE_SERVER "buildah tag $DOCKERHUB_IMAGE $PRIVATE_IMAGE"

echo "  → Retag complete. SHA256 hash unchanged."
echo ""

# ── Step 4: Push to private registry ─────────────────────────────────────────
echo "──────────────────────────────────────────────"
echo "  Ready to push:"
echo "  $PRIVATE_IMAGE"
echo "──────────────────────────────────────────────"
echo ""
read -p "  Proceed with push to private registry? (y/n): " CONFIRM_PUSH
echo ""

if [[ "$CONFIRM_PUSH" != "y" && "$CONFIRM_PUSH" != "Y" ]]; then
    echo "  Aborted by user. Image tagged but not pushed."
    echo ""
    exit 0
fi

echo "[ 4 / 5 ]  Push to private registry"
echo "  → Logging in to $PRIVATE_REGISTRY..."

ssh $IMAGE_SERVER "buildah login $PRIVATE_REGISTRY --username $REGISTRY_USERNAME --password $REGISTRY_PASSWORD"

echo "  → Login successful."
echo "  → Pushing $PRIVATE_IMAGE..."
echo ""

ssh $IMAGE_SERVER "buildah push $PRIVATE_IMAGE"

echo ""
echo "  → Push complete."
echo ""

# ── Step 5: Pull to local machine ─────────────────────────────────────────────
echo "[ 5 / 5 ]  Pull to local machine"
echo "  → Pulling $PRIVATE_IMAGE from private registry..."
echo ""

podman pull $PRIVATE_IMAGE

echo ""
echo "  → Pull complete."
echo ""

# ── Update POSTMORTEM_IMAGE in ~/.bashrc ──────────────────────────────────────
echo "  → Updating POSTMORTEM_IMAGE in ~/.bashrc..."

sed -i '/POSTMORTEM_IMAGE/d' ~/.bashrc
echo "export POSTMORTEM_IMAGE=$PRIVATE_IMAGE" >> ~/.bashrc
source ~/.bashrc

echo "  → POSTMORTEM_IMAGE set to: $PRIVATE_IMAGE"
echo ""
echo "══════════════════════════════════════════════"
echo "  Successfully updated to $VERSION"
echo ""
echo "  Run: postmortemcli start"
echo "══════════════════════════════════════════════"
echo ""