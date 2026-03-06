build:
  mvn package -Dspotless.apply.skip=true -DskipTests
  docker build -t kernel .

compile:
  mvn compile -Dspotless.apply.skip=true

clean:
  mvn clean
