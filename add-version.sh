#!/bin/bash

# Show help
if [[ "$1" =~ "-h" ]] || [[ "$1" == '--help' ]]; then
  echo "Usage: ./add-version.sh vX.Y.Z"
  echo "Example: ./add-version.sh v0.1.4"
  exit 0
fi

# Validate version format
if [[ ! "$1" =~ ^v[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
  echo "❌ Invalid version format. Use: vX.Y.Z (e.g. v1.0.0)"
  exit 1
fi

# Add new version tag and push
echo "🏷  Tagging version: $1"
git tag "$1"
git push origin "$1"

# Force update 'latest' tag
echo "🔄 Updating 'latest' tag"
git tag -f latest
git push origin latest --force

echo "✅ Done!"

