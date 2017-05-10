![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)

<!-- MarkdownTOC depth="3" autolink="true" bracket="round"-->

- [nMix User Guide](#nmix-user-guide)
	- [Overview](#overview)
		- [Components](#components)
		- [Protocol](#protocol)
		- [Bulletin board structure](#bulletin-board-structure)
	- [Installing](#installing)
		- [Requirements](#requirements)
		- [Keys](#keys)
		- [Bulletin Board setup](#bulletin-board-setup)
		- [Trustee setup](#trustee-setup)
	- [Running an election](#running-an-election)
		- [Election configuration](#election-configuration)
	- [Artifact reference](#artifact-reference)
	- [FAQ](#faq)
		- [Is nMix 100% secure?](#is-nmix-100%25-secure)
		- [Is nMix end-to-end verifiable?](#is-nmix-end-to-end-verifiable)
		- [What about the use of SHA1 in the Git hash chain?](#what-about-the-use-of-sha1-in-the-git-hash-chain)
		- [What about the Registry, Ballotbox and Voting Booth? Where can I find them?](#what-about-the-registry-ballotbox-and-voting-booth-where-can-i-find-them)
		- [Does nMix include a threshold cryptosystem?](#does-nmix-include-a-threshold-cryptosystem)
		- [Could you replace the Git bulletin board with a Blockchain/IPFS/Tahoe-Lafs/Swarm?](#could-you-replace-the-git-bulletin-board-with-a-blockchainipfstahoe-lafsswarm)
		- [Where can I ask more questions?](#where-can-i-ask-more-questions)

<!-- /MarkdownTOC -->


## nMix User Guide

This document contains detailed information necessary to set up and run elections with nMix. If you prefer a quick hands-on introduction, check out the [quickstart tutorial](tutorial.md).

### Overview
The following is a typical voting setup using nMix

![nMix setup](http://davidruescas.com/wp-content/uploads/2017/04/nMixSetup3.png)

The nMix system components can be seen below the dotted line. The nMix software itself runs on the trustees, which cooperatively execute the protocol posting artifacts to the bulletin board, backed by Git.
#### Components
Following are the main components as seen above, some of these are external to nMix.
###### Registry
This component handles the authentication and registration of voters. The Registry is responsible for the electoral roll, which is the list of eligible voters for an election. This component is external to nMix.
###### Ballotbox
Serves the (typically javascript based) voting booth interface and collects votes. Only votes cast by eligible voters, as determined by the Registry, are allowed. Votes are encrypted at the voting booth with the election public key, jointly created by the Trustees prior to the election. Once the voting period is over, the Ballotbox publishes the set of ballots to the Bulletin Board. This component is external to nMix.
###### Bulletin Board
The Bulletin Board maintains the list of information artifacts necessary for the execution of the cryptographic protocol. This includes artifacts related to joint key generation, ballot casting, ballot mixes, and joint decryption, as well as all required mathematical proofs. The Bulletin Board is implemented with Git's hash-chain, and is immutable and tamper resistant.
###### Trustee
Trustees cooperate to execute the voting protocol such that its privacy and verifiability properties are guaranteed. These properties are inherited from the nMix design, which in turn is based on the univote specification. Trustees are custodians of election private keys that safeguard vote secrecy. When executing the protocol, Trustees retrieve information published and collected by the Bulletin Board. Trustees run the nMix software.
#### Protocol
The main steps of the protocol are
1. The election configuration is defined and posted to the bulletin board.

2. Trustees individually validate and sign the election configuration.

3. Trustees jointly generate the public and private key shares of the election public key.

4. Trustees mutually validate each other's shares and proofs of correctness.

5. Trustees construct, validate and sign the election public key.

6. Voter's cast votes encrypted the election public key signed by all trustees (this step occurs outside of nMix).

7. The encrypted cast votes (ciphertexts) are uploaded to the nMix bulletin board.

8. The trustees execute the mix chain, constructing sequential mixes of the ciphertexts.

9. The trustees mutually validate each other's mix and proofs of correctness.

10. The trustees perform joint decryption of the ciphertexts produced at the end of the mixnet.

11. The trustees mutually validate each other's decryptions and proofs of correctness.

12. The trustees construct, validate and sign the plaintexts resulting from decryption.

These steps are performed per election item. Note that the nMix protocol does not include steps related to the Registry and Ballotbox (except 6. above, for clarity). nMix only interfaces with external components in three ways

1. To receive the Election Configuration, presumably defined by some election authority.

2. To provide the election public key used to encrypt votes at the Voting Booth

3. To receive the encrypted votes collected by the Ballotbox.

Details related to voter registration and authentication are critical to a secure voting system, but they are decoupled from the nMix design and considered given.

#### Bulletin board structure
The bulletin board structure can be roughly divided into three parts, corresponding to root data, trustee data and ballotbox data. Root data defines the global configuration. The trustee and ballotbox areas contain data posted by their respective components.
##### BNF grammar
The bulletin board structure can be described in Backus-Naus form as
```
<board> ::= "" | <entry> | <entry> "," <entry>
<entry> ::= <root_entry> | <trustee_entry> | <ballotbox_entry>
<root_entry> ::= <root_path> <root_artifact>
<trustee_entry> ::= <trustee_path> <trustee_artifact>
<ballotbox_entry> ::= <ballotbox_path> <ballotbox_artifact>
<root_path> ::= "/"
<trustee_path> ::= "/" <trustee> "/" <item> "/"
<ballotbox_path> ::= "/bb/"
<root_artifact> ::= "error" | "pause"
<trustee_artifact> ::= "error" | <trustee_artifact_name> <artifact_type> | "mix" <mix_artifact_type>
<trustee_artifact_name> ::= "share" | "public_key" | "decryption" | "plaintexts"
<artifact_type> ::= ".json" | ".stmt.json" | "stmt.sig.ucb"
<mix_artifact_type> ::= ".json" | ".stmt.json" | "." <trustee> ".sig.ucb"
<ballotbox_artifact> ::= <ballotbox_artifact_name> <artifact_type>
<ballotbox_artifact_name> ::= "ballots"
<trustee> ::= <integer>
<item> ::= <integer>
```

##### Example
The following is an example of a populated bulletin board after the execution of the entire protocol

TODO
### Installing
As seen above, an nMix installation is composed of one machine acting as a bulletin board together with 2 or more machines acting as trustees. The trustees must have have ssh access connectivity to the bulletin board server.

#### Requirements
The following software is required to run nMix

* Java 8+ (on trustees)
* Git version 2.4+ (on the bulletin board server)

nMix has been tested against Ubuntu 16.04.

#### Keys
This section offers an overview of the cryptographic keys necessary for nMix installation. Specific configuration steps are listed in the [bulletin board](#bulletin-board-setup) and [trustee](#trustee-setup) set up sections.

nMix uses RSA keys for authentication and to sign protocol artifacts. Additionally, symmetric AES keys are used to encrypt election key private shares.

##### RSA keys

Trustees authenticate against the bulletin board using their private RSA key. The corresponding public key must be known to the bulletin board server for the trustee to gain access. In the current implementation this behaviour is implemented through git's ssh authentication mechanism which uses linux's authorized_keys file. See the bulletin board setup for configuration details.

Additionally, trustees use RSA keys to sign and mutually verify artifacts posted and retrieved from the bulletin board. Part of the election setup is specifying which trustees will take part in the protocol, and the definition of a shared configuration file which lists these RSA public keys. Finally, trustees must configure an individual list of RSA public keys that indicates the trustees they are willing to cooperate with. See the trustee configuration for details.

Although strictly not part of the nMix backend, the Ballotbox must also use an RSA public key to authenticate against the bulletin board as well as to sign the set of ballots cast by voters. Recall that uploading of ballots occurs at step 7 of the protocol.

##### AES keys

During protocol execution trustees generate public and private shares of the election public key. The election public key is used to encrypt ballots when casting votes. At the end of the eleciton, trustees jointly decrypt the ballots once they have been mixed, preserving anonymity. This joint decryption uses the private shares created at the joint key generation phase. Private shares are encrypted using an AES key.

##### Key summary

The following table summarizes the use of keys in nMix.

|Location   |Type|Format|Purpose
|---|---|---|---
|Trustee .ssh directory|RSA Private key|SSH|Authentication of trustees on bulletin board
|Bulletin board authorized_keys|RSA Public key|SSH|Authentication of trustees on bulletin board
|Trustee configuration|RSA Private key|PEM|Signature of protocol artifacts
|Trustee configuration|RSA Public key|PEM|Self verification of protocol artifacts
|Trustee configuration|RSA Public key list|PEM|Acceptance of trustees to cooperate with
|Trustee configuration|AES key|RAW|Encryption of private key shares
|Election Configuration|RSA Public key list|PEM|Mutual verification of protocol artifacts
|Election Configuration|RSA Public key|PEM|Verification of ballots artifact

#### Bulletin Board setup
The nMix bulletin board component is just a git server. Setting up the bulletin board is simply setting up a git server with special attention paid to security and authentication. nMix uses ssh authentication based on the authorized_keys mechanism. The required steps are

1. Setup a git server as per the official [git documentation](https://git-scm.com/book/en/v2/Git-on-the-Server-Setting-Up-the-Server)
2. Ensure that the shell for the git user is set to [git-shell](https://git-scm.com/docs/git-shell). This prevents any login attempts.
3. Ensure that trustees have ssh connectivity to the bulletin board server.
4. Add trustee RSA public keys to the authorized_keys file for the git user. These are generated as part of the trustee [set up](#trustee-setup).
5. Optionally configure firewall settings to accept ssh connections only from known trustees.

You may consult the [quickstart tutorial](tutorial.md) for an example of how to set up a git server. Please note that this is only to be used as an example.

##### Git compression
By default, git applies two types of compression to objects stored and sent across the network, one of these does not scale over cpu cores. Compression may be suboptimal on a fast network and if disk space is not a problem. In order to disable git compression on the bulletin board server

###### Disabling git compression

```
git config --global pack.window 0
git config --global core.bigFileThreshold 1

git config --global core.compression 0
git config --global core.looseCompression 0
git config --global pack.compression 0
```

#### Trustee setup
Trustees run the nMix software itself. You must build and then configure nMix for each trustee participating in an election.

##### Build
The first step is to build the project

1 Clone the repository

```git clone https://github.com/nVotes/nMix.git```

2 In order to compile the source you will need to [install sbt](http://www.scala-sbt.org/release/docs/Setup.html). Once you have sbt, build with

```sbt assembly assemblyPackageDependency```

Install rng-tools for random number generation

3 Install rng-tools

```apt-get install rng-tools```

##### Configuration
Trustee configuration is specified in a file, typically named application.conf. You can find a reference configuration file in [src/main/resources/application.conf.dist](https://github.com/nVotes/nMix/blob/master/src/main/resources/application.conf.dist) from which to write your own. nMix will look
for this configuration file

1. At the location passed in with -Dconfig.file=<application.conf>
2. On the classpath, with name application.conf

The easiest procedure is to

1. Copy application.conf.dist to your own application.conf
2. Edit the file and apply necessary changes
3. Specify the location of this file in the run.sh script

Please refer to the reference configuration file for details about each configuration value.

##### Generating trustee keys
The script _src/main/shell/keys.sh_ can be used to generate the five keys needed for each trustee, these are

* RSA private key in SSH format
* RSA public key in SSH format
* RSA private key in PEM format
* RSA public key in PEM format
* AES key in raw format

##### Libmix settings
nMix uses the libmix library for core cryptography operations, with support for multicore cpus. The following settings control libmix optimizations

###### libmix.gmp=true/false

Activates native implementation of modular exponentiation and legendre symbol via
[jna-gmp](https://github.com/square/jna-gmp) and gmp. The jna-gmp library is included with
nMix.

###### libmix.extractor=true/false

Activates automatic extraction and parallelization of modular exponentiation calls.

###### libmix.parallel-generators=true/false

Activates parallel computation of generators used in Terelius-Wikstrom proofs (experimental)

##### Git compression
By default, git applies two types of compression to objects stored and sent across the network, one of these does not scale over cpu cores. Compression may be suboptimal on a fast network and if disk space is not a problem. In order to disable git compression on the trustee

###### Disabling git compression

```
-Dnmix.git.disable-compression=true
```

### Running an election
TODO

#### Election configuration
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
Creating and posting this data to the bulletin board is the first step that kicks off the rest of the protocol execution. Besides the configuration itself, a statement file must be provided which will be signed by trustees indicating acceptance of its parameters. The statement config file has this structure

```
{"configHash":"<the sha-512 hash of the configuration's json representation as a string>"}
```

nMix provides a utility to generate these two files correctly. For example, from the sbt console
```
runMain org.nvotes.trustee.GenConfig <election name> <public key bits> <items> <path to ballotbox rsa public key pem> <path to trustees rsa public key pems, concatenated>
```

will produce the Election Configuration, _config.json_, and the statement file, _config.stmt.json_.

These two files can then be posted to the bulletin board, executing step 1 of the protocol.

### Artifact reference
TODO
### FAQ
####  Is nMix 100% secure?
No, no computer or software system is 100% secure. nMix is secure in the specific sense that it employs cryptographic techniques to achieve strong privacy and verifiability properties, as defined in the academic literature.

#### Is nMix end-to-end verifiable?
nMix provides the core cryptography to construct an end-to-end verifiable voting system. In particular, it provides a bulletin board and a verifiable mix-net together with zero knowledge proofs. These are key ingredients necessary for granting recorded-as-cast and counted-as-recorded verifiablity. When combined with suitable external components the whole system becomes end-to-end verifiable.

#### What about the use of SHA1 in the Git hash chain?
The choice of git as a hash-chain was made with full awareness of the status of SHA-1, which will not be a problem because:

a) Git will [transition](https://plus.google.com/+LinusTorvalds/posts/7tp2gYWQugL) away from SHA-1

b) It is always possible to build a hash-chain manually with any choice of secure hash on top of git.
####  What about the Registry, Ballotbox and Voting Booth? Where can I find them?
nMix implements the cryptographic core of a voting system, and does not include these software components. You can either

a) Wait for these components to be developed by us.

b) Write them yourself (they are the comparatively 'easier' parts to develop). Also, a lot of work can be taken from [Agora Voting](https://github.com/agoravoting) which is a stable, in production system with over 1.5 million votes tallied.

c) Work with us to develop them, nMix is an open source project!
####  Does nMix include a threshold cryptosystem?
The current version of nMix uses a _distributed_ cryptosystem (which is a special case of a threshold system where t = n). All trustees must cooperate to complete the protocol. However, adding a threshold cryptosystem is on the table, and mostly depends on development resources and funding.
####  Could you replace the Git bulletin board with a Blockchain/IPFS/Tahoe-Lafs/Swarm?
Yes, in theory. The nMix protocol has been designed to decouple the crypto workflow from the bulletin board, relying only on authenticated get and put primitives. If these primitives are supported by another bulletin board implementation the replacement should be possible. See [here](TODO) for a high level design along those lines, with IPFS as a backend.

####  Where can I ask more questions?

Ask your question on the [mailing list](https://groups.google.com/forum/#!forum/nmix-voting) and we'll add it to this FAQ.