![alt text](http://davidruescas.com/wp-content/uploads/2017/04/nMix.png)

# Quickstart demo

The demo directory contains data and scripts to run a full election cycle on a single machine, from key generation all the way to joint ballot decryption.

### Set up the machine as a git server.

First create the /srv/data directory if it does not exist

```mkdir /srv/data```

then create the git user

```useradd --create-home --skel /dev/null --home-dir /srv/data/git --shell /usr/bin/git-shell git```

this allows serving requests via ssh, but will block attempts at login.

### Add necessary public keys to git's authorized_keys.

The user under which you run the demo must have their public key added to the git user's _authorized_keys_ file. First create the .ssh directory for the git user.

```mkdir /srv/data/git/.ssh```

Then add a key, for example

```cat $HOME/.ssh/id_rsa.pub >> /srv/data/git/.ssh/authorized_keys```

NOTE: you should NOT use the keys in the 'keys' subfolder of the demo for anything; these keys are used only for the DEMO and should be removed after you've finished testing it.

### Initialize the repository

Run the setup.sh script (as root) which will initialize the repository with files necessary for the election

```./setup.sh```

### Build the project + rng-tools

1. Clone the repository

```git clone https://github.com/nVotes/nMix.git```

2. In order to compile the source you will need to [install sbt](http://www.scala-sbt.org/release/docs/Setup.html). Once you have sbt, build with

```sbt assembly assemblyPackageDependency```

Then install rng-tools for random number generation

3. Install rng-tools

```apt-get install rng-tools```
### Start the protocol by running the trustees

To do this

```./run1.sh```

runs the first trustee. And

```./run2.sh```

runs the second trustee. The protocol is reactive, the trustees will execute operations whenever they detect work needs to be done on the bulletin board. Trustees can be stopped and started at any point, they will automatically resume work wherever it was left off. They also don't need to run simultaneously or even overlap.

When they are first run, the trustees will execute operations for config signing, key share generation, public key creation, and public key signing. Once these phases are complete, the trustees will idle, as they have no work to do.

It is then time to simulate the voting process by adding ballots to the bulletin board.

### Add encrypted ballots

For example, add 1000 encrypted ballots

```./ballots.sh 1000```

Once the ballots are on the bulletin board, the trustees will automatically begin the mixing process and continue operating all the way up to the joint decryption and signing of plaintexts. This may take a while [depending](benchmarks.md) on the number of ballots you have generated. Once finished, the trustees will again idle.

### Done!

You can inspect the results of the demo by browsing through the files produced in the repository. There should be plaintexts files if the process has ended correctly. To reset the process, simply execute the setup script again. One way to monitor what's going on during execution is

```while :; do tree datastore/repo --noreport; sleep 3; done```

which will show you the contents of the repository periodically. You can also try the [pViz](https://github.com/ruescasd/pViz) tool, which provides a simple visualization of the protocol on a browser.

Although the demo is set up for 2 trustees and 3 ballot sets, you can extend it to run with more authorities and ballot sets.