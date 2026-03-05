build:
  # mvn package
  mvn package -Dspotless.apply.skip=true -DskipTests
  docker build -t elvis .
