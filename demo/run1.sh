#!/bin/bash

# you must have run the assembly and assemblyPackageDependency commands from sbt for this to work
CLASSPATH=../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT-deps.jar

MAINCLASS=org.nvotes.trustee.TrusteeLoop

# for the demo we are disabling the singleton port so that two instances can run on the same machine
OPTIONS="-Dconfig.file=application.conf -Dnmix.singleton.port=-1"
OPTIMIZATIONS="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true -Dnmix.git.disable-compression=true"

java -Xmx4G -Xms4G $OPTIONS $OPTIMIZATIONS -classpath $CLASSPATH $MAINCLASS $*

