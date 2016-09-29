# TCP BBR Quick-Start: Building and Running TCP BBR on Google Compute Engine

Google recently contributed BBR ("Bottleneck Bandwidth and RTT"), a new
congestion control algorithm, to the the Linux kernel TCP stack. The commit
description in the
[Linux TCP BBR commit](http://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git/commit/?id=0f8782ea14974ce992618b55f0c041ef43ed0b78)
describes the background, motivation, design, and example performance results
for BBR.

This tutorial shows how to download, compile, configure, and install a Linux
kernel running TCP BBR on Google Compute Engine.

## Prerequisites:

 * A working Google Compute Engine (GCE) account (you can sign up for a [free trial](https://cloud.google.com/free-trial/))
 * A working install of [google-cloud-sdk](https://cloud.google.com/sdk/)


### Create a Ubuntu LTS 16.04 VM

Let's start by declaring some shell variables relating to your GCE environment:

```
typeset -x PROJECT="make-tcp-fast"    # A GCE project name
typeset -x ZONE="us-west1-a"          # A GCE Zone

```

Next, we can create a VM to build the kernel with BBR. This will create a
high-cpu instance with SSD disks to compile our kernel:

```
gcloud compute \
  instances create "bbrtest" \
  --project ${PROJECT} --zone ${ZONE} \
  --machine-type "n1-highcpu-8" \
  --network "default" \
  --maintenance-policy "MIGRATE" \
  --boot-disk-type "pd-ssd" \
  --boot-disk-device-name "bbrtest" \
  --image "/ubuntu-os-cloud/ubuntu-1604-xenial-v20160922" \
  --boot-disk-size "20" \
  --scopes default="https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring.write","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly"

```
After creating the instance; log in:


```
gcloud compute ssh --project ${PROJECT} --zone ${ZONE} bbrtest

```

Use apt(8) to install the packages necessary to build a kernel (answer `Y` and
press `Enter` when prompted by `apt-get`):


```
sudo apt-get update
sudo apt-get build-dep linux
sudo apt-get upgrade
```

## Obtain kernel sources with BBR

Since BBR was only recently contributed to Linux, we'll need to compile a
development kernel that includes this feature. It is also important that we
follow the
[kernel/image requirements for GCE](https://cloud.google.com/compute/docs/tutorials/building-images).

For this guide, we'll grab the Linux networking development branch
`davem/net-next` from `git.kernel.org`. First, let's prepare to clone the
sources into /usr/src/net-next and do the configuration and compliation
as a mortal (non-root) user.

```
# Make /usr/src writeable/sticky like /tmp
cd /usr/src && sudo chmod 1777 .
```

Using `git`, clone a copy of the kernel sources:

```
git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
cd /usr/src/net-next
```

## Configure the kernel

Covering the details of kernel-configuration for
GCE is beyond the scope of this document.  Ensure you
have a kernel configuration compatible with GCE. This is
documeneted in detail at [Building a Compute Engine Image From Scratch](https://cloud.google.com/compute/docs/tutorials/building-images).

Then ensure the options `CONFIG_TCP_CONG_BBR` and `CONFIG_NET_SCH_FQ` are
enabled for this kernel:


```
egrep '(CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ)=' .config

CONFIG_TCP_CONG_BBR=y
CONFIG_NET_SCH_FQ=y

```

If you do not yet have a kernel config for GCE, you can try the [config included
in this tutorial](config.gce). You can copy it to your test machine with:

```
gcloud compute copy-files --project ${PROJECT} --zone ${ZONE}  config.gce $USER@bbrtest:/usr/src/net-next/
```

## Compile the kernel

Compile the kernel:

```
cd /usr/src/net-next
mv config.gce .config
make prepare
make -j`nproc`
make -j`nproc` modules
```

## Configure the machine

Configure the machine, changing the default qdisc to fq, and default TCP
congestion control to BBR:

```
sudo bash -c 'echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf'
sudo bash -c 'echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf'
```

##  Install the kernel and reboot

Install the kernel on this machine, and reboot:

```
sudo make modules_install install
sudo reboot now
```

## Verify the kernel and configuration

Confirm that you have booted the kernel we compiled; I get this result:

```
ncardwell@bbrtest:~$ uname -a
Linux bbrtest 4.8.0-rc7+ #1 SMP Thu Sep 29 20:06:31 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

Confirm that the fq qdisc is installed:

```
tc qdisc show
```

Confirm that BBR is being used:

```
sysctl net.ipv4.tcp_congestion_control
```

Enjoy!
