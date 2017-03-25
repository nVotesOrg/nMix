#!/bin/bash

# you must have run the assembly and assemblyPackageDependency commands from sbt for this to work
CLASSPATH=../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT.jar:../target/scala-2.12/nMix-assembly-0.2-SNAPSHOT-deps.jar

MAINCLASS=org.nvotes.trustee.Continuous

OPTIONS="-Dconfig.file=application.conf"
OPTIMIZATIONS="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true -Dnmix.git.disable-compression=true"

java -Xmx4G -Xms4G $OPTIONS $OPTIMIZATIONS -classpath $CLASSPATH $MAINCLASS $*
