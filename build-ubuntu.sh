#!/bin/bash
# Build Linux kernel tarball for Ubuntu machines.

set -e

usage() {
	echo "build-ubuntu.sh"
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
LOCALVERSION=+${BRANCH}+${SHA1}
PKG_DIR=${PWD}/gce/${LOCALVERSION}/pkg
INSTALL_DIR=${PWD}/gce/${LOCALVERSION}/install
BUILD_DIR=${PWD}/gce/${LOCALVERSION}/build
KERNEL_PKG=kernel-${LOCALVERSION}.tar.gz2
MAKE_OPTS="-j`nproc` \
           CC=clang\
           LOCALVERSION=${LOCALVERSION}"

#           INSTALL_PATH=${INSTALL_DIR}/boot \
#           INSTALL_MOD_PATH=${INSTALL_DIR}"

echo "cleaning..."
mkdir -p ${BUILD_DIR}
mkdir -p ${INSTALL_DIR}/boot
mkdir -p ${PKG_DIR}

ORIGINAL_CONFIG="config.5.15.0-48-generic-ubuntu"

set +e

echo "copying ${ORIGINAL_CONFIG} to .config ..."
cp ${ORIGINAL_CONFIG} .config

echo "setting desired config parameters ..."
scripts/config --disable DEBUG_INFO \
               --enable DEBUG_INFO_NONE \
               --enable CONFIG_ASHMEM \
               --set-str SYSTEM_TRUSTED_KEYS "" \
               --set-str CONFIG_SYSTEM_REVOCATION_KEYS "" \
               --module CONFIG_TCP_CONG_PRAGUE \
               --module CONFIG_TCP_CONG_BBR \
               --module CONFIG_TCP_CONG_BBR2 \
               --module CONFIG_TCP_CONG_DCTCP \
               --module CONFIG_NET_IPIP \
               --module CONFIG_NET_CLS_U32 \
               --module CONFIG_NET_SCH_DUALPI2 \
               --module CONFIG_NET_SCH_PIE \
               --module CONFIG_NET_SCH_FQ \
               --module CONFIG_NET_SCH_FQ_CODEL \
               --module CONFIG_NET_SCH_CODEL \
               --module CONFIG_NET_SCH_RED \
               --module CONFIG_NET_SCH_CAKE \
               --module CONFIG_NET_SCH_HTB \
               --module CONFIG_NET_SCH_NETEM \
               --module CONFIG_NET_SCH_INGRESS \
               --module CONFIG_NET_ACT_MIRRED \
               --module CONFIG_IFB \
               --module CONFIG_VETH \
               --module CONFIG_BRIDGE \
               --module CONFIG_INET_DIAG

echo "making ..."
make ${MAKE_OPTS} bindeb-pkg > /tmp/make.bindeb-pkg

echo "done."
exit 0
