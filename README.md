# packetdrill
This is the official Google release of packetdrill.

The packetdrill scripting tool enables quick, precise tests for entire TCP/UDP/IPv4/IPv6 network stacks, from the system call layer down to the NIC hardware. packetdrill currently works on Linux, FreeBSD, OpenBSD, and NetBSD. It can test network stack behavior over physical NICs on a LAN, or on a single machine using a tun virtual network device.

The code is GPLv2. Currently the source for the testing tool and a number of test scripts is in the git repository. We will continue to post more tests from our team's Linux TCP test suite (described in our USENIX paper), as time permits.

Links:
* [the Google packetdrill git repository is now on github.com](https://github.com/google/packetdrill)
* [packetdrill USENIX ATC paper from June 2013](http://research.google.com/pubs/pub41316.html) describing the tool and our team's experiences
* [packetdrill USENIX ;login: article](http://research.google.com/pubs/pub41848.html) from October 2013
* [packetdrill mailing list](https://groups.google.com/forum/#!forum/packetdrill) for questions, discussions and patches
* [packetdrill language syntax reference](syntax.wiki)

External links:
* [using packetdrill for teaching TCP](http://beta.computer-networking.info/syllabus/default/exercises/tcp-2.html)

# How To Submit a Patch for packetdrill

We welcome patches with bug fixes or new features for packetdrill. The packetdrill project uses git for source code management. Please follow the following steps when sending in a patch for packetdrill:

1. join the packetdrill e-mail list, so your e-mails to the list will be accepted by Google groups
2. edit some files, compile, test
3. verify that you can certify the origin of this code with a `Signed-off-by` footer, according to the [standards of the Linux open source project](https://www.kernel.org/doc/html/v4.17/process/submitting-patches.html#developer-s-certificate-of-origin-1-1)
4. git commit your change with a message like:
 
 ```
packetdrill: add amazing feature foo

This commit adds amazing feature foo, which ...

Tested on FooOS and BarOS by doing the following:
  ...

Signed-off-by: John Doe <john.doe@gmail.com>
```

5. Generate git patches using: `git format-patch HEAD~1`
6. Check style for the patches by running `checkpatch.pl` from the Linux source tree, e.g.:
```
wget http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/plain/scripts/checkpatch.pl
chmod u+x checkpatch.pl
./checkpatch.pl --no-tree --ignore FSF_MAILING_ADDRESS 00*.patch
```
7. You can submit your patch as either a GitHub pull request or an e-mail patch series, with something like:
```
git send-email --to packetdrill@googlegroups.com 00*.patch
```
