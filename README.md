![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)
# nMix: Mixnet-based secure voting

nMix is an open source backend for a mixnet-based, cryptographically secure voting system featuring strong privacy and verifiability properties. It is an implementation of the core [univote](https://e-voting.bfh.ch/projects/univote/) specification, with a few changes.

## Cryptographic scheme

The main elements of the cryptographic scheme are

* ElGamal homomorphic distributed cryptosystem
* Verifiable re-encryption mixnet
* Joint key-generation / decryption with correctness proofs
* Tamper-resistant bulletin board hash-chain
* RSA message signing and trustee authentication

Together with suitable cryptographic mechanisms at the voting booth this produces an [end-to-end verifiable](https://en.wikipedia.org/wiki/End-to-end_auditable_voting_systems) voting system. More details of the scheme can be found [here](http://davidruescas.com/?p=3651).

## Software architecture

nMix follows a minimal design, composed of

* An append-only bulletin board backed by Git
* A reactive, data-driven election protocol specified declaratively
* A minimal rule engine for boolean expression conditions
* [libmix](https://github.com/ruescasd/libmix) (including [unicrypt](https://github.com/bfh-evg/univote2)) library for multicore support

which allows for

* Fault tolerance through stateless and idempotent trustees
* Auditability and tamper resistance via Git's hashchain
* Simple network toplogy: centralized communication on a single ssh port
* Simple software deployment: Java8 (+ Git on the bulletin board server)

Below is an example for a 2-authority mixnet setup

![sample deployment](http://davidruescas.com/wp-content/uploads/2017/04/Untitled-Diagram.png)

## Requirements

* Java 8+
* Git version 2.4+ (on the bulletin board server)
* Gmp (for native modular arithmetic, optional)

## Installing

Clone the repository

```git clone https://github.com/nVotes/nMix.git```

Install rng-tools

```apt-get install rng-tools```

In order to build the project you will need to [install sbt](http://www.scala-sbt.org/release/docs/Setup.html). To build

```sbt assembly assemblyPackageDependency```

## Quickstart demo

The demo directory contains data and scripts to run a full election cycle on a single machine,
from key generation all the way to joint ballot decryption.

* Set up the machine as a git server. First create the /srv/data directory if it does not exist

```mkdir /srv/data```

then create the git user

```useradd --create-home --skel /dev/null --home-dir /srv/data/git --shell /usr/bin/git-shell git```

this allows serving requests via ssh, but will block attempts at login. This
command needs to be executed as root.

Once the user has been created, the setup.sh script (as root) will initialize the repository
and add files necessary to start the demo.

```./setup.sh```

To re-run a demo you can simply execute setup.sh again to reset everything.

* Add necessary public keys to git's authorized_keys. The user under which
you run the demo must have their public key added to that file. First create the
.ssh directory for the git user.

```mkdir /srv/data/git/.ssh```

Then add a key, for example

```cat $HOME/.ssh/id_rsa.pub >> /srv/data/git/.ssh/authorized_keys```

NOTE: you should NOT use the keys in the 'keys' subfolder for anything,
these keys are used merely for the DEMO and should be removed after
you've finished testing it.

* Install rng-tools (if you haven't already)

```apt-get install rng-tools```

* Compile the project (see [here](http://www.scala-sbt.org/0.13/docs/Installing-sbt-on-Linux.html) to install sbt)

```sbt```
```assembly```
```assemblyPackageDependency```

which will create the necessary jars in the target directory. These jars are
referenced by the scripts below.

* Run the trustees, with the run1.sh, run2.sh scripts.

Once you've run setup.sh, you can begin the election process. To do this

```./run1.sh```

runs the first trustee. And

```./run2.sh```

runs the second trustee. The protocol is reactive, the trustees will execute operations whenever
they detect work needs to be done on the bulletin board. Note that trustees can be stopped and started
at will, they will automatically pick up work wherever it was left off. They also don't need to
run simultaneously or overlap at any moment, it is enough that they run at _some_ point.

When they are first run, the trustees will execute operations for config signing, key share generation,
public key creation, and public key signing. Once these phases are complete, the trustees will
idle, as they have no work to do.

It is then time to simulate the voting process by adding ballots to the bulletin board. This is done with

```./ballots.sh <number of ballots>```

Once the ballots are on the bulletin board, the trustees will automatically begin the mixing process
and continue operating all the way up to the joint decryption and signing of plaintexts.

You can inspect the results of the demo by browsing through the files produced in the repository.
There should be plaintexts files if the process has ended correctly. To restart the process, simply
execute the setup script again. One way to inspect what's going on during execution is

```while :; do tree datastore/repo --noreport; sleep 3; done```

which will show you the contents of the repository periodically.

Although the demo is set up for 2 trustees and 3 ballot sets, you can extend it to run with more
authorities and ballot sets. Note that if you run a large number of ballots through the demo you may
require large amounts of processing time and memory. This could require adjusting the jvm options.

It is also straightforward to run the demo with remoting, just adjust application.conf accordingly.

## User guide
--
### Overview
The following is a typical voting setup using nMix

![nMix setup](http://davidruescas.com/wp-content/uploads/2017/04/nMixSetup2.png)

#### Election Configuration
--
#### Trustee Configuration
Several trustee configuration options are listed below.
##### Libmix settings
The following settings control libmix optimizations

###### libmix.gmp=true/false

Activates native implementation of modular exponentiation and legendre symbol via
[jna-gmp](https://github.com/square/jna-gmp) and gmp, if available on the system.

###### libmix.extractor=true/false

Activates automatic extraction and parallelization of modular exponentiation calls.

###### libmix.parallel-generators=true/false

Activates parallel computation of generators used in Terelius-Wikstrom proofs (experimental)
##### Git compression
By default, git applies two types of compression to objects stored and sent across the network, one of these does not scale over cpu cores. Compression may be suboptimal on a fast network and if disk space is not a problem. In order to disable git compression

###### Disabling git compression - git server

```
git config --global pack.window 0
git config --global core.bigFileThreshold 1

git config --global core.compression 0
git config --global core.looseCompression 0
git config --global pack.compression 0
```

###### Disabling git compression - nMix trustee

```-Dnmix.git.disable-compression=true```

## EC2 Benchmarks

|Date   |Configuration    |Hardware   |Heap   |Libmix opt.|Trustee opt.|Time(s)
|---|---|---|---|---|---|---|
|   |   |   |   |   | ||