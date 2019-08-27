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
Google Cloud instance to compile our kernel:

```
gcloud compute \
  instances create "bbrtest1" \
  --project ${PROJECT} --zone ${ZONE} \
  --machine-type "n1-standard-8" \
  --network "default" \
  --maintenance-policy "MIGRATE" \
  --boot-disk-type "pd-standard" \
  --boot-disk-device-name "bbrtest1" \
  --image "/ubuntu-os-cloud/ubuntu-1604-xenial-v20160922" \
  --boot-disk-size "20" \
  --scopes default="https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring.write","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly"
```
After creating the instance; log in:


```
gcloud compute ssh --project ${PROJECT} --zone ${ZONE} bbrtest1
```

Then, on your GCE instance, use apt(8) to install the packages necessary to
build a kernel (answer `Y` and press `Enter` when prompted by `apt-get`):


```
sudo apt-get update
sudo apt-get build-dep linux
sudo apt-get upgrade
```

## Obtain kernel sources with TCP BBR

TCP BBR is in Linux v4.9 and beyond. However, we recommend compiling from the
latest sources, from the networking development branch. In particular, the
`davem/net-next` networking development branch (and Linux v4.20 and beyond)
support
[TCP-level pacing](https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=218af599fa635b107cfe10acf3249c4dfe5e4123).
This means that there is no longer a strict requirement to install the "fq"
qdisc to use BBR. Any qdisc will work, though "fq" performs better for
highly-loaded servers. (Note that TCP-level pacing was added in v4.13-rc1 but
did not work well for BBR until a
[fix](https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=cadefe5f584abaac40dce72009e4de738cbff467)
was added in 4.20.)

For this guide, we'll grab the Linux networking development branch
`davem/net-next` from `git.kernel.org`.

On your GCE instance, use `git` to clone the Linux sources into
/usr/src/net-next and do the configuration and compliation as a mortal
(non-root) user:

```
# Make /usr/src writeable/sticky like /tmp:
cd /usr/src && sudo chmod 1777 .
# Clone a copy of the kernel sources:
git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git
cd /usr/src/net-next
```

## Configure the kernel

If you do not yet have a Linux kernel config for GCE, you can try the
[config included in this tutorial](https://raw.githubusercontent.com/google/bbr/master/Documentation/config.gce).
On your GCE instance you can download that kernel config and then update that
config to select the defaults for any new config options added recently:

```
cd /usr/src/net-next
wget -O .config https://raw.githubusercontent.com/google/bbr/master/Documentation/config.gce
make olddefconfig
```

## Compile the kernel

Compile the kernel, on your GCE instance:

```
cd /usr/src/net-next
make prepare
make -j`nproc`
make -j`nproc` modules
```

##  Install the kernel and reboot

On your GCE instance, install the newly-compiled kernel and reboot:

```
cd /usr/src/net-next
sudo make -j`nproc` modules_install install
sudo reboot now
```

## Verify the kernel and configuration

On your GCE instance, confirm that it has booted the kernel we compiled:

```
uname -a
```

That should show something like the following, except with a version number and
build timestamp matching the kernel you compiled above:

```
Linux bbrtest1 4.8.0-rc7+ #1 SMP Thu Sep 29 20:06:31 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

Finally, on your GCE instance, confirm that BBR is being used:

```
sysctl net.ipv4.tcp_congestion_control
```

Enjoy!

## Further reading

If you already have a kernel config for GCE, then you can just enable BBR,
rebuild, and reboot. On your GCE instance, check that if you run:

```
cd /usr/src/net-next
egrep '(_BBR)' .config
```

then you see exactly the following lines:

```
CONFIG_TCP_CONG_BBR=y
CONFIG_DEFAULT_BBR=y
```

If you want to create your own .config, then just remember to include those two
lines, and follow the
[kernel/image requirements for GCE](https://cloud.google.com/compute/docs/tutorials/building-images).

If you have questions about BBR, check the [BBR FAQ](https://github.com/google/bbr/blob/master/Documentation/bbr-faq.md).
