# Build kernel inside tacplus container, then build kernel container.

registry := "registry.gitlab.com/secondstarcavalier/controlplane/services/kernel"
tacplus_image := "registry.gitlab.com/secondstarcavalier/controlplane/services/tacplus/tacplus-1-1:latest"

default: build container

build:
  #!/usr/bin/env bash
  set -euo pipefail
  proto_mount=""
  if [ -d "../proto" ]; then
    proto_mount="-v $(cd ../proto && pwd):/proto:ro"
  fi
  docker run --rm \
    -v "$(pwd)":/workspace \
    $proto_mount \
    -v "${HOME}/.m2:/root/.m2" \
    -w /workspace \
    {{tacplus_image}} \
    bash -c '
      src=""
      if [ -d /proto ]; then src="--src /proto"; fi
      (cd tacplus && tacplus build $src)
      mvn package -DskipTests
    '

container:
  #!/usr/bin/env bash
  set -euo pipefail
  tag=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
  major=$(echo "$tag" | cut -d. -f1)
  minor=$(echo "$tag" | cut -d. -f2)
  image="{{registry}}/kernel-${major}-${minor}:latest"
  docker build -t "$image" .
  echo "Built: $image"
