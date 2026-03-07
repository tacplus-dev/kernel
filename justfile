proto_dir := "../proto"
proto_repo := "git@gitlab.com:secondstarcavalier/controlplane/services/proto.git"

build:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -d "{{proto_dir}}" ]; then
    echo "Cloning proto..."
    git clone {{proto_repo}} {{proto_dir}}
  fi
  cd server && tacplus build -c tacplus-local.yaml
  mvn package -Dspotless.apply.skip=true -DskipTests
  docker build -t kernel .

compile:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -d "{{proto_dir}}" ]; then
    echo "Cloning proto..."
    git clone {{proto_repo}} {{proto_dir}}
  fi
  cd server && tacplus build -c tacplus-local.yaml
  mvn compile -Dspotless.apply.skip=true

clean:
  mvn clean
