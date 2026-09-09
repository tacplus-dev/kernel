# Local development builds only — not used in CI/CD.

TACPLUS := env_var_or_default("TACPLUS_BIN", "tacplus")

# The protoc `generate` pins, read from the one protobuf pin in pom.xml so the
# compiler and the runtime can never drift apart. protoc gencode declares a
# MINIMUM protobuf runtime version and the runtime refuses gencode newer than
# itself, so regenerating with whatever protoc is on PATH (Homebrew ships 36.1)
# against protobuf-java 4.36.0 does not fail with a version error: it fails as
# an ExceptionInInitializerError from the protobuf runtime check, several frames
# below anything that names a version, on most of the test suite at once.
PROTOBUF_VERSION := `sed -n 's:.*<protobuf.version>\(.*\)</protobuf.version>.*:\1:p' pom.xml`

default: generate

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  # tacplus resolves protoc as PROTOC_BINARY, then PATH (tacplus
  # pkg/internal/tactype/config.go ResolveProtocBinary), so the env var covers
  # every protoc invocation it makes, descriptor parsing included. protoc reads
  # its well-known types from <binary>/../include, so the bin/include pair below
  # has to be assembled: the Maven protoc artifact is the bare executable, and
  # the matching .proto sources ship inside protobuf-java of the same version.
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)   classifier=osx-aarch_64 ;;
    Darwin/x86_64)  classifier=osx-x86_64 ;;
    Linux/aarch64)  classifier=linux-aarch_64 ;;
    Linux/x86_64)   classifier=linux-x86_64 ;;
    *) echo "no pinned protoc for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
  esac
  toolchain="$PWD/target/protoc"
  rm -rf "$toolchain"
  mkdir -p "$toolchain/bin" "$toolchain/include"
  mvn -q dependency:copy \
    -Dartifact=com.google.protobuf:protoc:{{PROTOBUF_VERSION}}:exe:"${classifier}" \
    -DoutputDirectory="$toolchain/bin"
  mv "$toolchain/bin/protoc-{{PROTOBUF_VERSION}}-${classifier}.exe" "$toolchain/bin/protoc"
  chmod +x "$toolchain/bin/protoc"
  mvn -q dependency:copy \
    -Dartifact=com.google.protobuf:protobuf-java:{{PROTOBUF_VERSION}}:jar \
    -DoutputDirectory="$toolchain"
  (cd "$toolchain/include" && unzip -oq "$toolchain/protobuf-java-{{PROTOBUF_VERSION}}.jar" 'google/protobuf/*.proto')
  export PROTOC_BINARY="$toolchain/bin/protoc"
  "$PROTOC_BINARY" --version
  {{TACPLUS}} build --tag latest

verify:
  {{TACPLUS}} verify

clean:
  rm -rf tacplus/target codegen/target server/target target
