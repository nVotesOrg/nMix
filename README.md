# nMix

A backend for a mixnet-based, cryptographically secure voting system. It is an implementation
of the core [univote](https://e-voting.bfh.ch/projects/univote/) specification, with a few changes.

## Design

nMix follows a minimal design, composed of

* An append-only bulletin board backed by Git
* A reactive, data-driven election protocol specified by boolean expression rules
* A minimal rule engine
* Fully stateless, choreographed trustees
* nMixlib (including [unicrypt](https://github.com/bfh-evg/univote2)) libraries

yielding the following properties (besides the crypto specification)

* Fault tolerance through stateless and idempotent trustees
* Auditability and tamper resistance via Git's hashchain
* Simple network toplogy: centralized communication on a single ssh port
* Simple software deployment: Java8 (+ Git on the bulletin board server)
* Instantaneous backups during protocol execution

## Requirements

* Java 8+
* Git version 2.4+ (on the bulletin board server)
* Gmp for native modular arithmetic (optional)

## Demo setup

The demo directory contains data and scripts to run a full election cycle on
a single machine, from key generation all the way to joint ballot decryption.

* Set up the machine as a git server, you can do this with this command

```useradd --create-home --skel /dev/null --home-dir /srv/data/git --shell /usr/bin/git-shell git```

this allows serving requests via ssh, but will block attempts at login. This
command needs to be executed as root.

Once the user has been created, the setup.sh script will initialize the
repository and add files necessary to start the demo. To re-run a demo you
can simply execute setup.sh again to reset everything.

```./setup.sh```

* Add necessary public keys to git's authorized_keys. The user under which
you run the demo must have their public key added to that file. For example

```cat $HOME/.ssh/id_rsa.pub >> /srv/data/git/.ssh/authorized_keys```

* Compile the project, using this command from the project root

```sbt assembly assemblyPackageDependency```

which will create the necessary jars in the target directory. These jars are
referenced by the scripts below.

* Run the trustees, with the run1.sh, run2.sh and ballots.sh scripts.

Once you've run setup.sh, you can begin the eleciton process. To do this

```./run1.sh```

runs the first trustee. And

```./run2.sh```

runs the second trustee. The protocol is reactive, the trustees will
execute operations whenever they detect work needs to be done on the bulletin
board. Note that trustees can be stopped and  started at will, they will
automatically pick up work wherever it was left off. They also don't need to
run simultaneously or overlap at any moment, it is enough that they run
at _some_ point.

When they are first run, the trustees will execute operations
for config signing, key share generation, public key creation, and
public key signing. Once these phases are complete, the trustees will
idle, as they have no work to do.

It is then time to simulate the voting process by adding ballots to the
bulletin board. This is done with

```./ballots.sh <number of ballots>```

Once the ballots are on the bulletin board, the trustees will automatically
pick up the work, and begin the mixing process and continue work all the
way up to the joint decryption and signing of plaintexts.

You can inspect the results of the demo easily by browsing through the
files produced in the repository. There should be plaintexts files if
the process has ended correctly. To restart the process, simply execute
the setup script again.

Although the demo is set up for 2 trustees and 3 ballot sets, you can extend
to run with more authorities and ballot sets. Note that if you run a large
number of ballots through the demo you may require large amounts of processing
time and memory. This could require adjusting the jvm options.

### Randomness
To speed up HybridRandomByteSequence under linux install rng-tools.