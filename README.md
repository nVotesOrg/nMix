![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png) [![Build Status](https://travis-ci.org/travis-ci/travis-web.svg?branch=master)](https://travis-ci.org/travis-ci/travis-web)
# nMix: Mixnet-based secure voting

nMix is an open source backend for a mixnet-based, cryptographically secure voting system, featuring strong privacy and verifiability properties. It is a reactive implementation of the core [univote](https://e-voting.bfh.ch/projects/univote/) crypto specification, with a few changes.

### Cryptographic scheme

The main elements of the cryptographic scheme are

* ElGamal homomorphic distributed cryptosystem[1][5]
* Verifiable re-encryption mixnet with Terelius-Wikstrom shuffles[2][3][6]
* Joint key-generation / decryption with zero knowledge correctness proofs[5]
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

### Quickstart

The best place to start is to follow the [tutorial](https://github.com/nVotes/nMix/blob/master/docs/tutorial.md). You can
run an election demo on a single machine without having to do a real world distributed deployment.

### Documentation

* [Tutorial](https://nvotesorg.github.io/nMix/tutorial.html)
* [User guide](https://nvotesorg.github.io/nMix/guide.html)
* [FAQ](https://nvotesorg.github.io/nMix/guide.html#faq)
* [Performance benchmarks](https://nvotesorg.github.io/nMix/benchmarks.html)

### Getting help

* You can ask questions on the [mailing list](https://groups.google.com/forum/#!forum/nmix-voting).

### Acknowledgements

* [Rolf Haenni](https://web.ti.bfh.ch/?id=hnr1&L=2) and his [team](https://e-voting.bfh.ch/) for the unicrypt and univote projects.
* [Douglas Wikstrom](http://www.csc.kth.se/~dog/) for his thoughtful advice and discussions.

### Licensing

nMix is licensed under the terms of the GNU Affero General Public License (GNU AGPLv3).

---
##### Crypto references

[1] T. Elgamal. A public key cryptosystem and a signature scheme based on discrete logarithms. IEEE Transactions on Information Theory, 1985.

[2] B. Terelius and D. Wikstrom. Proofs of Restricted Shuffles. In D. J. Bernstein and T. Lange, editors, AFRICACRYPT’10, 3rd International Conference on Cryptology in Africa, LNCS 6055, pages 100–113, Stellenbosch, South Africa, 2010.

[3] D. Wikstrom. A Commitment-Consistent Proof of a Shuffle. In C. Boyd and J. Gonzalez Nieto, editors, ACISP’09, 14th Australasian Conference on Information Security and Privacy, LNCS 5594, pages 407–421, Brisbane, Australia, 2009.

[4] P. Locher, R. Haenni. A lightweight implementation of a shuffle proof for electronic voting systems. 2014

[5] https://github.com/bfh-evg/univote2/raw/development/doc/report/report.pdf

[6] David Chaum, Untraceable electronic mail, return addresses, and digital pseudonyms, Comm. ACM, 24, 2, 1981.

[7] https://en.wikipedia.org/wiki/Linked_timestamping

[8] R. Rivest, A. Shamir, L. Adleman.  A method for obtaining digital signatures and public-key cryptosystems. 1978.
