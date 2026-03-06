build:
  mvn package -Dspotless.apply.skip=true -DskipTests
  cd core && docker build -t kernel-core .
  cd edge && docker build -t kernel-edge .

build-core:
  mvn package -pl common,core -Dspotless.apply.skip=true -DskipTests
  cd core && docker build -t kernel-core .

build-edge:
  mvn package -pl common,edge -Dspotless.apply.skip=true -DskipTests
  cd edge && docker build -t kernel-edge .

compile:
  mvn compile -Dspotless.apply.skip=true

clean:
  mvn clean
