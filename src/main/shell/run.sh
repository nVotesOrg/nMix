#!/bin/bash

# This file is part of nMix.
# Copyright (C) 2015-2016-2017  Agora Voting SL <agora@agoravoting.com>

# nMix is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# nMix  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with nMix.  If not, see <http://www.gnu.org/licenses/>.

# This script runs the nMix protocol on a trustee.
# Note that this process runs indefinitely and will
# idle if no work is required.

# Set the path where the assembly and dependency jars are found
# The default value works for running the script from the root
# of an nMix cloned directory once the assembly and assemblyPackageDependency
# sbt commands have been run
JAR_HOME=target/scala-2.12/

# The classpath points to both the assembly and dependency jars
CLASSPATH=$JAR_HOME/nMix-assembly-0.2-SNAPSHOT.jar:$JAR_HOME/nMix-assembly-0.2-SNAPSHOT-deps.jar

# The class that runs the protocol for a trustee
MAINCLASS=org.nvotes.mix.TrusteeLoop

# Specify where the configuration file is found
OPTIONS="-Dconfig.file=application.conf"
# Set libmix optimization values
OPTIMIZATIONS="-Dlibmix.gmp=true -Dlibmix.extractor=true -Dlibmix.parallel-generators=true"

# Runs the trustee.
# You may need to resize the heap space for large numbers of ciphertexts
# Please refer to the benchmark document in the docs folder for estimations
java -Xmx4G -Xms4G $OPTIONS $OPTIMIZATIONS -classpath $CLASSPATH $MAINCLASS repo