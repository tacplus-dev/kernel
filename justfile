# Local development builds only — not used in CI/CD.

src_flag := if path_exists("../../proto") == "true" { "--src ../../proto" } else { "" }

default:
  tacplus build {{src_flag}} -- -DskipTests

clean:
  rm -rf tacplus/target codegen/target server/target target

verify:
  tacplus verify
