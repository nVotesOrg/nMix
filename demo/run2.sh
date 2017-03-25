#!/bin/bash

# you must have run the assembly and assemblyPackageDependency commands from sbt for this to work
CLASSPATH=../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT-deps.jar

MAINCLASS=org.nvotes.trustee.Continuous

OPTIONS="-Dconfig.file=application.conf -Ddata-store-path=datastore2 -Dpublic-key=keys/auth2.pub.pem -Dprivate-key=keys/auth2.pem"
OPTIMIZATIONS="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true"


java -Xmx2G -Xms2G $OPTIONS $OPTIMIZATIONS -classpath $CLASSPATH $MAINCLASS $*
