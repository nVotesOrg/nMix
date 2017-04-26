![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)
# nMix: Mixnet-based secure voting

nMix is an open source backend for a mixnet-based, cryptographically secure voting system, featuring strong privacy and verifiability properties. It is a reactive implementation of the core [univote](https://e-voting.bfh.ch/projects/univote/) crypto specification, with a few changes.

### Cryptographic scheme

The main elements of the cryptographic scheme are

* ElGamal homomorphic distributed cryptosystem[1][5]
* Verifiable re-encryption mixnet[2][3][6]
* Joint key-generation / decryption with correctness proofs[5]
* Tamper-resistant bulletin board hash-chain[7]
* RSA message signing and trustee authentication[8]

Together with suitable cryptographic mechanisms at the voting booth this produces an [end-to-end verifiable](https://en.wikipedia.org/wiki/End-to-end_auditable_voting_systems) voting system. More details of the scheme can be found [here](http://davidruescas.com/?p=3651).

### Software architecture

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

![sample deployment](http://davidruescas.com/wp-content/uploads/2017/04/nMix2.png)

### Requirements

* Java 8+
* Git version 2.4+ (on the bulletin board server)

### Installing

Clone the repository

```git clone https://github.com/nVotes/nMix.git```

Install rng-tools

```apt-get install rng-tools```

In order to build the project you will need to [install sbt](http://www.scala-sbt.org/release/docs/Setup.html). Once you have sbt, build with

```sbt assembly assemblyPackageDependency```

### Quickstart demo

The demo directory contains data and scripts to run a full election cycle on a single machine, from key generation all the way to joint ballot decryption.

##### 1. Set up the machine as a git server.

First create the /srv/data directory if it does not exist

```mkdir /srv/data```

then create the git user

```useradd --create-home --skel /dev/null --home-dir /srv/data/git --shell /usr/bin/git-shell git```

this allows serving requests via ssh, but will block attempts at login.

##### 2. Add necessary public keys to git's authorized_keys.

The user under which you run the demo must have their public key added to the git user's _authorized_keys_ file. First create the .ssh directory for the git user.

```mkdir /srv/data/git/.ssh```

Then add a key, for example

```cat $HOME/.ssh/id_rsa.pub >> /srv/data/git/.ssh/authorized_keys```

NOTE: you should NOT use the keys in the 'keys' subfolder for anything, these keys are used merely for the DEMO and should be removed after you've finished testing it.

##### 3. Initialize the repository

Run the setup.sh script (as root) which will initialize the repository with files necessary for the election

```./setup.sh```

##### 4. Start the protocol by running the trustees

To do this

```./run1.sh```

runs the first trustee. And

```./run2.sh```

runs the second trustee. The protocol is reactive, the trustees will execute operations whenever they detect work needs to be done on the bulletin board. Trustees can be stopped and started at any point, they will automatically resume work wherever it was left off. They also don't need to run simultaneously or even overlap.

When they are first run, the trustees will execute operations for config signing, key share generation, public key creation, and public key signing. Once these phases are complete, the trustees will idle, as they have no work to do.

It is then time to simulate the voting process by adding ballots to the bulletin board.

##### 5. Add encrypted ballots

For example, add 1000 encrypted ballots

```./ballots.sh 1000```

Once the ballots are on the bulletin board, the trustees will automatically begin the mixing process and continue operating all the way up to the joint decryption and signing of plaintexts. This may take a while depending on the number of ballots you have generated. Once finished, the trustees will again idle.

##### 6. Done!

You can inspect the results of the demo by browsing through the files produced in the repository. There should be plaintexts files if the process has ended correctly. To reset the process, simply execute the setup script again. One way to monitor what's going on during execution is

```while :; do tree datastore/repo --noreport; sleep 3; done```

which will show you the contents of the repository periodically.

Although the demo is set up for 2 trustees and 3 ballot sets, you can extend it to run with more authorities and ballot sets.

### Documentation

* [User guide](https://github.com/nVotes/nMix/blob/master/docs/GUIDE.md)

### Benchmarks

|Date   |Trustees|Ballots    |Public key bits |Hardware**   |Heap   |Libmix opt.|Trustee opt.*|Time (min)
|---|---|---|---|---|---|---|---|---|
|3/21   |2   |3 x 100k   |2048   |2 x m4.16, 1 x m4.10   |5G|all |NNNN|92
|3/25   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |NYNN|72
|3/27   |2   |3 x 100k   |2048   |2 x m4.16,1 x m4.10   |10G|all |YYNN|59

*The Trustee optimization settings column has the following syntax.
```
Permuted mix assignment=Y/N
Disable git compression=Y/N
Offline phase=Y/N
Parallel actions=Y/N
```
Not all code changes and optimizations are reflected in this column.

**Hardware specs described in terms of [EC2 instance types](https://aws.amazon.com/ec2/instance-types/)

### Acknowledgements

We'd like to thank
* Rolf Haenni and his [team](https://e-voting.bfh.ch/) for the unicrypt and univote projects.
* [Douglas Wikstrom](http://www.csc.kth.se/~dog/) for his thoughtful advice and discussions.

### Licensing

nMix is licensed under the terms of the GNU Affero General Public License (GNU AGPLv3).

---
##### References

[1] T. Elgamal. A public key cryptosystem and a signature scheme based on discrete logarithms. IEEE Transactions on Information Theory, 1985.

[2] B. Terelius and D. Wikstrom. Proofs of Restricted Shuffles. In D. J. Bernstein and T. Lange, editors, AFRICACRYPT’10, 3rd International Conference on Cryptology in Africa, LNCS 6055, pages 100–113, Stellenbosch, South Africa, 2010.

[3] D. Wikstrom. A Commitment-Consistent Proof of a Shuffle. In C. Boyd and J. Gonzalez Nieto, editors, ACISP’09, 14th Australasian Conference on Information Security and Privacy, LNCS 5594, pages 407–421, Brisbane, Australia, 2009.

[4] P. Locher, R. Haenni. A lightweight implementation of a shuffle proof for electronic voting systems. 2014

[5] https://github.com/bfh-evg/univote2/raw/development/doc/report/report.pdf

[6] David Chaum, Untraceable electronic mail, return addresses, and digital pseudonyms, Comm. ACM, 24, 2, 1981.

[7] https://en.wikipedia.org/wiki/Linked_timestamping

[8] R. Rivest, A. Shamir, L. Adleman.  A method for obtaining digital signatures and public-key cryptosystems. 1978.