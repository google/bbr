[![.github/workflows/kernel.yml](https://github.com/L4STeam/linux/workflows/bindeb-pkg/badge.svg)](https://github.com/L4STeam/linux/actions)
# Linux kernel tree with L4S patches

This linux kernel repository contains the various patches developed in the
context of the L4S experiment.

Namely:
- The dualQ coupled AQM (see branch sch_dualpi2, as well as the
[iproute2 repository](https://github.com/L4STeam/iproute2)
- An implementation of Accurate ECN (see branch AccECN-full)
- The base implementation of TCP Prague (see branch tcp_prague)
- ECT(1) enabled DCTCP
- ECT(1) enabled BBR v2 (from v2alpha branch in
[BBR v2 repo](https://github.com/google/bbr))

# Installation (debian derivatives)

```bash
wget https://github.com/L4STeam/linux/releases/download/testing-build/l4s-testing.zip
unzip l4s-testing.zip
sudo dpkg --install debian_build/*
sudo update-grub  # This should auto-detect the new kernel
# You can now reboot (and may have to manually select the kernel in grub)
# Be sure to ensure the required modules are loaded before doing experiments, e.g.,
sudo modprobe sch_dualpi2
sudo modprobe tcp_prague
```

## This branch (testing)

This branch accumulates all patches into a single kernel tree, in order to ease
up testing.

You can grab a pre-built debian archive of the kernel image and headers through
the latest [actions artifacts](https://github.com/L4STeam/linux/actions). The tip of the master branch is also always build/packaged (alongside iproute2) and attached as pre-release artifact for the `testing-build` tag.

## Compilation

Compile it as any kernel, enabling the dualpi2 AQM and TCP Prague in the config.

Assuming you compile this on a similar machine that where you intend to run the
kernel (e.g., architecture, distribution, ...):
```bash
# Try to use existing kernel config
if [ -f /proc/config.gz ]; then
    zcat proc/config.gz > .config
    make olddefconfig
else if [ -f "/boot/config-$(uname -r)" ]; then
    cp "/boot/config-$(uname -r)" .config
    make olddefconfig
else
    make defconfig
fi

# Enable TCP Prague and dualpi2
scripts/config -m TCP_CONG_PRAGUE
scripts/config -m NET_SCH_DUALPI2
# Optionally enable DCTCP and BBR v2
scripts/config -m TCP_CONG_DCTCP
scripts/config -m TCP_CONG_BBR2

# Build the kernel
make -j$(nproc) LOCALVERSION=-prague-1
# Alternatively, you can generate *.deb with
# BUILD_NUMBER=${BUILD_NUMBER:-1} make \
#	-j$(nproc) bindeb-pkg \
#	LOCALVERSION=-prague-${BUILD_NUMBER} \
#	KDEB_PKGVERSION=1
# see the output of `make help` to generate rpms/...

# Install it on the current system if applicable
make install
make modules_install

# Update your bootloader to list the new kernel
update-grub
# You may then want to udpate the GRUB_DEFAULT variable
# in /etc/default/grub to the newly installed kernel
```

If you intend to use non-default parameters for dualpi2,
make sure to also build the [patched iproute2 ](https://github.com/L4STeam/iproute2), e.g.,
```bash
git clone https://github.com/L4STeam/iproute2.git && cd iproute2
./configure
make
tc/tc qdisc replace dev eth0 root dualpi2 ...
# You can optionally install (!potentially overwrite) the new
# iproute2 utils with `make install`
```

## Performing experiments

While dualpi2 can work with DCTCP, DCTCP suffers from a few unfortunate
interactions with GSO/pacing/..., resulting in under-utilization. As a result,
we advice you to use tcp_prague which currently has
basic fixes to those limitations. Note that this might still under-perform in
heavily virtualized settings, as scheduling becomes less reliable.

```bash
sysctl -w net.ipv4.tcp_congestion_control=prague
# Enable Accurate ECN
sysctl -w net.ipv4.tcp_ecn=3
```

Prague attempts to negotiate Accurate ECN automatically.
Note that, at the moment, Accurate ECN **must** be enabled on both ends of a
connection in order it with DCTCP or BBR v2.
