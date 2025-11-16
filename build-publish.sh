#!/bin/sh

# VERSION file path
VERSION_FILE="VERSION"

# Parse command line arguments
NO_CACHE=""
if [ "$1" = "--no-cache" ]; then
    NO_CACHE="--no-cache"
    echo "Building with --no-cache flag"
fi

# Check if VERSION file exists, if not create it with version 1
if [ ! -f "$VERSION_FILE" ]; then
    echo "1" > "$VERSION_FILE"
    echo "Created VERSION file with initial version 1"
fi

# Read current version from file
CURRENT_VERSION=$(cat "$VERSION_FILE" 2>/dev/null)

# Validate that the version is a number
if ! echo "$CURRENT_VERSION" | grep -qE '^[0-9]+$'; then
    echo "Error: Invalid version format in $VERSION_FILE. Expected a number, got: $CURRENT_VERSION"
    exit 1
fi

# Increment version
VERSION=$((CURRENT_VERSION + 1))

echo "Building version $VERSION (incrementing from $CURRENT_VERSION)"

# Build the image with optional --no-cache flag
# CR_PAT is required for installing mazza-base from private GitHub repo
docker build $NO_CACHE --build-arg CR_PAT=$CR_PAT --platform linux/amd64 -t ghcr.io/jmazzahacks/api-gatekeeper:$VERSION .

# Tag the same image as latest
docker tag ghcr.io/jmazzahacks/api-gatekeeper:$VERSION ghcr.io/jmazzahacks/api-gatekeeper:latest

# Push both tags
docker push ghcr.io/jmazzahacks/api-gatekeeper:$VERSION
docker push ghcr.io/jmazzahacks/api-gatekeeper:latest

# Update the VERSION file with the new version
echo "$VERSION" > "$VERSION_FILE"
echo "Updated $VERSION_FILE to version $VERSION"
