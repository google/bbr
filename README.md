# TCP BBR v3 Release

This document gives a quick overview of Google's TCP BBR v3 release for Linux,
and how to download, build, install, and test it.

The TCP BBR v3 release is intended to enable research collaboration and wider
testing.  We encourage researchers to dive in and help evaluate/improve the BBR
algorithm and code. We welcome patches with good solutions to issues.

This document shows how to download, build, install, and test
a Linux kernel running TCP BBR v3.

## License

Like Linux TCP BBR v1, the v3 code is dual-licensed as both GPLv2 (like the
Linux kernel) and BSD. You may use it under either license.

## Viewing the TCP BBR v3 sources

You can view the current sources here:
[tcp_bbr.c](https://github.com/google/bbr/blob/v3/net/ipv4/tcp_bbr.c)

## Obtaining kernel sources with TCP BBR v3

There are two main options for downloading the code:

1. To create a new git repo starting from a Linux kernel with TCP BBR v3,
you can run:

```
git clone -o google-bbr -b v3  https://github.com/google/bbr.git
cd bbr/
```

2. To download the code into an existing git repo, you can use:

```
git remote add google-bbr https://github.com/google/bbr.git
git fetch google-bbr
git checkout google-bbr/v3
```

Note that if you already have a git repo that has imported the Linux source
tree, then the second option will be much faster and use much less space, since
it will only need to download the small deltas relative to the mainline Linux
source distribution.

## Building and installing the kernel

To build a Linux kernel with TCP BBR v3 support, copy that kernel to a target
(Debian or Ubuntu) test machine (bare metal or GCE), and reboot that machine,
you can use the following script, included in the TCP BBR v3 distribution:

```
./gce-install.sh -m ${HOST}
```

## Checking the kernel installation

Once the target test machine has finished rebooting, then ssh to the target
test machine and become root with sudo or equivalent. First check that the
machine booted the kernel you built above:

```
uname -a
```

You should see the branch name SHA1 hash, and build time stamp from the kernel
you built above.


Then check what congestion control modules are available with:
```
sysctl net.ipv4.tcp_available_congestion_control
```

You should see something like:
```
net.ipv4.tcp_available_congestion_control = reno bbr cubic dctcp
```

## Install test dependencies

Next, copy the test scripts to the target test machine with:

```
scp -r gtests/net/tcp/bbr/nsperf/ ${HOST}:/tmp/
```

Before running the tests for the first time, as a one-time step you'll need to
install the dependencies on the test machine, as root:

```
mv /tmp/nsperf /root/
cd /root/nsperf
./configure.sh
```

## Running TCP BBR v3 tests and generating graphs

To run the tests, ssh to the target test machine and become root with sudo or
equivalent. Then run the tests and generate graphs with:

```
cd /root/nsperf
./run_tests.sh
./graph_tests.sh
```

This will run for hours, and place the graphs in the ./graphs/ directory.

You can run and graph a subset of the tests by specifying the test by name as
an environment variable. For example:

```
cd /root/nsperf
tests=random_loss ./run_tests.sh
tests=random_loss ./graph_tests.sh
```

Enjoy!

## Release Notes and Details

### Introducing the ecn_low per-route feature

This new "ecn_low" per-route feature indicates that the given destination
network is a low-latency ECN environment, meaning both that (a) ECN CE marks
are applied by the network using a low-latency marking threshold and also that
(b) TCP endpoints provide precise per-data-segment ECN feedback in ACKs (where
the ACK ECE flag echoes the received CE status of all newly-acknowledged data
segments). This feature indication can be used by congestion control algorithms
to decide how to interpret ECN signals over the given destination network.

Basically, this "ecn_low" feature is for use when you know that any ECN marks
that the connections experience will be DCTCP/L4S-style ECN marks, rather than
RFC3168 ECN marks.

A patch for the iproute2 package to support the "ecn_low" feature is included
in the BBRv3 source branch
[here](https://github.com/google/bbr/blob/v3/0002-ip-introduce-the-ecn_low-per-route-feature.patch)

### iproute2 patches to support functionality in the BBRv3 source release

The BBRv3 source release includes several patches for the iproute2 package to
support functionality in the BBRv3 test kernel:

- patch "ss" tool to output congestion control state for BBRv3:
  - [0001-ss-output-TCP-BBRv3-diag-information.patch](https://github.com/google/bbr/blob/v3/gtests/net/tcp/bbr/nsperf/0001-ss-output-TCP-BBRv3-diag-information.patch)
- patch "ip" tool to support ecn_low per-route feature:
  - [0002-ip-introduce-the-ecn_low-per-route-feature.patch](https://github.com/google/bbr/blob/v3/gtests/net/tcp/bbr/nsperf/0002-ip-introduce-the-ecn_low-per-route-feature.patch)
- patch "ss" tool to show "ecn_low" state in TCP socket:
  - [0003-ss-display-ecn_low-if-tcp_info-tcpi_options-TCPI_OPT.patch](https://github.com/google/bbr/blob/v3/gtests/net/tcp/bbr/nsperf/0003-ss-display-ecn_low-if-tcp_info-tcpi_options-TCPI_OPT.patch)

### Enabling ECN support

You can enable BBRv3 ECN support with commands like the following:

```
# 1: negotiate TCP ECN for active and passive connections:
sysctl net.ipv4.tcp_ecn=1
# 2: enable BBRv3 ECN logic using the "ecn_low" per-route feature, e.g. :
alias ip=/root/iproute2/iproute2/ip/ip
ip route change default via 192.168.0.100 dev ens4 features ecn_low
```

## FAQ

If you have questions about BBR, check the [BBR
FAQ](https://github.com/google/bbr/blob/master/Documentation/bbr-faq.md).
