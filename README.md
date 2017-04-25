![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)
# nMix: Mixnet-based secure voting

nMix is an open source backend for a mixnet-based, cryptographically secure voting system featuring strong privacy and verifiability properties. It is an implementation of the core [univote](https://e-voting.bfh.ch/projects/univote/) crypto specification, with a few changes.

## Cryptographic scheme

The main elements of the cryptographic scheme are

* ElGamal homomorphic distributed cryptosystem[1][5]
* Verifiable re-encryption mixnet[2][3][6]
* Joint key-generation / decryption with correctness proofs[5]
* Tamper-resistant bulletin board hash-chain[7]
* RSA message signing and trustee authentication[8]

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

![sample deployment](http://davidruescas.com/wp-content/uploads/2017/04/nMix2.png)

## Requirements

* Java 8+
* Git version 2.4+ (on the bulletin board server)

## Installing

Clone the repository

```git clone https://github.com/nVotes/nMix.git```

Install rng-tools

```apt-get install rng-tools```

In order to build the project you will need to [install sbt](http://www.scala-sbt.org/release/docs/Setup.html). Once you have sbt, build with

```sbt assembly assemblyPackageDependency```

## Quickstart demo

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

You can inspect the results of the demo by browsing through the files produced in the repository. There should be plaintexts files if the process has ended correctly. To reset the process, simply execute the setup script again. One way to inspect what's going on during execution is

```while :; do tree datastore/repo --noreport; sleep 3; done```

which will show you the contents of the repository periodically.

Although the demo is set up for 2 trustees and 3 ballot sets, you can extend it to run with more authorities and ballot sets. Note that if you run a large number of ballots through the demo you may require large amounts of processing time and memory. This could require adjusting the jvm options. It is also straightforward to run the demo with remoting, refer to the User guide below.

## User guide
This section contains detailed information necessary to set up and run elections with nMix.
### Overview
The following is a typical voting setup using nMix

![nMix setup](http://davidruescas.com/wp-content/uploads/2017/04/nMixSetup3.png)

The nMix system components can be seen below the dotted line. The nMix software itself runs on the trustees, which cooperatively execute the protocol posting artifacts to the bulletin board, backed by Git.
##### Components
Following are descriptions the main components as seen above. Some of these are external to nMix.
###### Registry
This component handles the authentication and registration of voters. The Registry is responsible for the electoral roll, which is the list of eligible voters for an election. This component is external to nMix.
###### Ballotbox
Serves the (typically javascript based) voting booth interface and collects votes. Only votes cast by eligible voters, as determined by the Registry, are allowed. Votes are encrypted at the voting booth with the election public key, jointly created by the Trustees prior to the election. Once the voting period is over, the Ballotbox publishes the set of ballots to the Bulletin Board. This component is external to nMix.
###### Bulletin Board
The Bulletin Board maintains the list of information artifacts necessary for the execution of the cryptographic protocol. This includes artifacts related to joint key generation, ballot casting, ballot mixes, and joint decryption, as well as all required mathematical proofs. The Bulletin Board is implemented with Git's hash-chain, and is immutable and tamper resistant.
###### Trustee
Trustees cooperate to execute the voting protocol such that its privacy and verifiability properties are guaranteed. These properties are inherited from the nMix design, which in turn is based on the univote specification. Trustees are custodians of election private keys that safeguard vote secrecy. When executing the protocol, Trustees retrieve information published and collected by the Bulletin Board. Trustees run the nMix software.
##### Protocol
The main steps of the protocol are
1) The election configuration is defined and posted to the bulletin board.
2) Trustees individually validate and sign the election configuration.
3) Trustees jointly generate the public and private key shares of the election public key.
4) Trustees mutually validate each other's shares and proofs of correctness.
5) Trustees construct, validate and sign the election public key.
6) Voter's cast votes encrypted the election public key signed by all trustees (this step occurs outside of nMix).
7) The encrypted cast votes (ciphertexts) are uploaded to the nMix bulletin board.
8) The trustees execute the mix chain, constructing sequential mixes of the ciphertexts.
9) The trustees mutually validate each other's mix and proofs of correctness.
10) The trustees perform joint decryption of the ciphertexts produced at the end of the mixnet.
11) The trustees mutually validate each other's decryptions and proofs of correctness.
12) The trustees construct, validate and sign the plaintexts resulting from decryption.

These steps are performed per election item. Note that the nMix protocol does not include steps related to the Registry and Ballotbox (except 6. above, for clarity). nMix only interfaces with external components in three ways

1) To receive the Election Configuration, presumably defined by some election authority.
2) To provide the election public key used to encrypt votes at the Voting Booth
3) To receive the encrypted votes collected by the Ballotbox.

Issues related to voter registration and authentication are critical to a secure voting system, but they are decoupled from the nMix design and taken as given.

### Election configuration
The Election Configuration specifies the election information, the security parameters of the election public key, and the participating trustees and ballotbox agents. It has this json encoded structure

```
{
"id":"<an alphanumeric id for the election>",
"name":"<a human readable name for the election>",
"modulus":"<the safe prime modulus p of the multiplicative subgroup G*p used for ElGamal encryption>",
"generator":"<the generator g of the multiplicative subgroup G*p used for ElGamal encryption>",
"items":<the number of ballot sets (for example, questions) in the election>,
"ballotbox":"<the RSA public key of the ballotbox>",
"trustees":["<a list of RSA public keys for each trustee>"]
}
```
Defining and posting this data to the bulletin board is the first step that kicks off the rest of the protocol execution. Besides the configuration itself, a statement file must be provided which will be signed by trustees indicating acceptance of its parameters. The statement config file has this structure

```
{"configHash":"<the sha-512 hash of the configuration's json representation as a string>"}
```

nMix provides a utility to generate these two files correctly. For example, from the sbt console
```
runMain org.nvotes.trustee.GenConfig <election name> <public key bits> <items> <path to ballotbox rsa public key pem> <path to trustees rsa public key pems, concatenated>
```

will produce the Election Configuration, _config.json_, and the statement file, _config.stmt.json_.

These two files can then be posted to the bulletin board, executing step 1 of the protocol.
### Bulletin Board server set up and configuration
--
### Trustee set up and configuration
--
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

### Artifact reference
--
### FAQ
#####  Is nMix 100% secure?
No, no computer or software system is 100% secure. nMix is secure in the specific sense that it employs cryptographic techniques to achieve strong privacy and verifiability properties, as defined in the academic literature.

##### Is nMix end-to-end verifiable?
nMix provides the core cryptography to construct an end-to-end verifiable voting system. In particular, it provides a bulletin board and a verifiable mix-net and zero knowledge proofs, which are key components necessary for granting recorded-as-cast and counted-as-recorded verifiablity. When combined with suitable external components the whole system becomes end-to-end verifiable. See the next question.

##### What about the use of SHA1 in the Git hash chain?
The choice of git as a hash-chain was made with full awareness of the status of SHA-1, which will not be a problem because:

a) Git will [transition](https://plus.google.com/+LinusTorvalds/posts/7tp2gYWQugL) away from SHA-1

b) It is always possible to build a hash-chain manually with any choice of secure hash on top of git.
#####  What about the Registry, Ballotbox and Voting Booth? Where can I find them?
nMix implements the cryptographic core of a voting system, and does not include these software components. You can either

a) Wait for these components to be developed by us.

b) Write them yourself (they are the comparatively 'easier' parts to develop). Also, a lot of work can be taken from [Agora Voting](https://github.com/agoravoting) which is a stable, production ready system.

c) Work with us to develop them, nMix is an open source project!
#####  Does nMix include a threshold cryptosystem?
The current version of nMix uses a _distributed_ cryptosystem (which is a special case of a threshold system where t = n). All trustees must cooperate to complete the protocol. However, adding a threshold cryptosystem is on the table, and mostly depends on development resources and funding.
#####  Could you replace the Git bulletin board with a Blockchain/IPFS/Tahoe-Lafs?
Yes, in theory. The nMix protocol has been designed to decouple the crypto workflow from the bulletin board, relying only on authenticated get and put primitives. If these primitives are supported by another bulletin board implementation the replacement should be possible. See [here](TODO) for a high level design along those lines, with IPFS as a backend.
## Benchmarks

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

#### Acknowledgements

We'd like to thank
* Rolf Haenni and his [team](https://e-voting.bfh.ch/) for the unicrypt and univote projects.
* [Douglas Wikstrom](http://www.csc.kth.se/~dog/) for his thoughtful advice and discussions.

#### Licensing

##### References

[1] T. Elgamal. A public key cryptosystem and a signature scheme based on discrete logarithms. IEEE Transactions on Information Theory, 1985.

[2] B. Terelius and D. Wikstrom. Proofs of Restricted Shuffles. In D. J. Bernstein and T. Lange, editors, AFRICACRYPT’10, 3rd International Conference on Cryptology in Africa, LNCS 6055, pages 100–113, Stellenbosch, South Africa, 2010.

[3] D. Wikstrom. A Commitment-Consistent Proof of a Shuffle. In C. Boyd and J. Gonzalez Nieto, editors, ACISP’09, 14th Australasian Conference on Information Security and Privacy, LNCS 5594, pages 407–421, Brisbane, Australia, 2009.

[4] P. Locher, R. Haenni. A lightweight implementation of a shuffle proof for electronic voting systems. 2014

[5] https://github.com/bfh-evg/univote2/raw/development/doc/report/report.pdf

[6] David Chaum, Untraceable electronic mail, return addresses, and digital pseudonyms, Comm. ACM, 24, 2, 1981.

[7] https://en.wikipedia.org/wiki/Linked_timestamping

[8] R. Rivest, A. Shamir, L. Adleman.  A method for obtaining digital signatures and public-key cryptosystems. 1978.