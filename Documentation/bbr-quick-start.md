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

Since BBR was only recently contributed to Linux, we'll need to compile a
development kernel that includes this feature.

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
[config included in this tutorial](https://raw.githubusercontent.com/google/bbr/master/Documentation/config.gce). You can download that kernel config with:

```
wget  https://raw.githubusercontent.com/google/bbr/master/Documentation/config.gce
```

You can copy that kernel config to your GCE instance from your local host with:

```
gcloud compute copy-files --project ${PROJECT} --zone ${ZONE}  config.gce $USER@bbrtest1:/usr/src/net-next/.config
```

Then, on your GCE instance, update the config to select the defaults for any
new config options added recently:

```
cd /usr/src/net-next
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

## Configure the machine

On your GCE instance, configure the system, changing the default qdisc to fq,
and default TCP congestion control to BBR:

```
sudo bash -c 'echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf'
sudo bash -c 'echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf'
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

Finally, on your GCE instance, confirm that the fq qdisc is installed and that
BBR is being used:

```
tc qdisc show
sysctl net.ipv4.tcp_congestion_control
```

Enjoy!

## Further reading

If you already have a kernel config for GCE, then you can enable BBR and
FQ. On your GCE instance, check that if you run:

```
cd /usr/src/net-next
egrep '(CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ)=' .config
```

then you see exactly the following lines:

```
CONFIG_TCP_CONG_BBR=y
CONFIG_NET_SCH_FQ=y
```

If you want to create your own .config, then just remember to include those two
lines, and follow the
[kernel/image requirements for GCE](https://cloud.google.com/compute/docs/tutorials/building-images).
