#!/bin/bash
# Install the software necessary to run and graph the tests in
# this directory. Tested on Ubuntu Linux.

set -x  # print commands before executing
set -e  # exit upon error

sudo apt update
sudo apt install -y python2
sudo apt install -y netperf
sudo apt install -y gnuplot-nox

# On Ubuntu 18.04.2 LTS, there are issues with the iproute2 binaries:
#  (1) the 'tc' binary  has a bug and cannot parse netem random loss rates
#  (2) the 'ss' tool is missing recent socket stats
# In addition, all off-the-shelf iproute2 binaries lack support for features
# added in BBRv3.
# So to use this testing tool we build our own iproute2 tools
# from the iproute2 sources, with patches from the BBRv3
# source tree:

sudo apt install -y pkg-config make bison flex

# Our project's patches for the iproute2 package are in this directory:
PATCH_DIR=`pwd`

sudo bash -c  "\
  mkdir -p /root/iproute2/; \
  cd /root/iproute2; \
  git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git; \
  cd ./iproute2/ ; \
  git checkout e91dfaaaea5f6c8e6f5746cac34f8b0f5d665870 ; \
  git am ${PATCH_DIR}/*patch ; \
  ./configure ; \
  make"
