#!/bin/bash
# Build a Linux kernel suitable for Neal's Dell XPS 13.
# This script is only known to work for Debian/Ubuntu-based Dell XPS 13.

set -e

usage() {
	echo "dell-xps-13-build.sh"
}

VERBOSE=""

while getopts "h?vm:p:z:" opt; do
	case "${opt}" in
		h|\?)
			usage
			exit 0
			;;
		v)
			VERBOSE="set -x"
			;;
	esac
done

umask 022

${VERBOSE}

BRANCH=`git rev-parse --abbrev-ref HEAD | sed s/-/+/g`
SHA1=`git rev-parse --short HEAD`
LOCALVERSION=+${BRANCH}+${SHA1}+DELL
DELL_PKG_DIR=${PWD}/gce/${LOCALVERSION}/pkg
DELL_INSTALL_DIR=${PWD}/gce/${LOCALVERSION}/install
DELL_BUILD_DIR=${PWD}/gce/${LOCALVERSION}/build
KERNEL_PKG=kernel-${LOCALVERSION}.tar.gz2
MAKE_OPTS="-j`nproc` \
           LOCALVERSION=${LOCALVERSION} \
           EXTRAVERSION="" \
           INSTALL_PATH=${DELL_INSTALL_DIR}/boot \
           INSTALL_MOD_PATH=${DELL_INSTALL_DIR}"

echo "cleaning..."
mkdir -p ${DELL_BUILD_DIR}
mkdir -p ${DELL_INSTALL_DIR}/boot
mkdir -p ${DELL_PKG_DIR}

ORIGINAL_CONFIG="config.dell-xps-13-laptop"

set +e
echo "copying ${ORIGINAL_CONFIG} to .config ..."
cp ${ORIGINAL_CONFIG} .config
echo "running make olddefconfig ..."
make olddefconfig               > /tmp/make.olddefconfig
make ${MAKE_OPTS} prepare         > /tmp/make.prepare
echo "making..."
make ${MAKE_OPTS}                 > /tmp/make.default
echo "making modules ..."
make ${MAKE_OPTS} modules         > /tmp/make.modules
echo "making install ..."
make ${MAKE_OPTS} install         > /tmp/make.install
echo "making modules_install ..."
make ${MAKE_OPTS} modules_install > /tmp/make.modules_install
set -e

echo "making tarball ..."
(cd ${DELL_INSTALL_DIR}; tar -cvzf ${DELL_PKG_DIR}/${KERNEL_PKG}  boot/* lib/modules/* --owner=0 --group=0  > /tmp/make.tarball)

echo "tarball is at: ${DELL_PKG_DIR}/${KERNEL_PKG}"

echo "suggest running something like:
$VERBOSE
sudo rm -rf /boot/*DELL /lib/modules/*DELL
sudo tar --no-same-owner -xzvf ${KERNEL_PKG} -C / > /tmp/tar.out.txt
cd /boot
for v in \$(ls vmlinuz-* | sed s/vmlinuz-//g); do
	sudo mkinitramfs -k -o initrd.img-\${v} \${v}
done
sudo update-grub
sudo reboot
"
umask 027
