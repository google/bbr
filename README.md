# BBRv3 installation guide for Linux machines

Official GitHub BBRv3 repository: https://github.com/google/bbr/blob/v3/README.md

Install the necessary libraries
```
$ yum update -y
$ yum groupinstall 'Development Tools' -y
$ yum install elfutils-libelf-devel bison flex openssl-devel openssl ncurses-devel zstd iperf3 wget net-tools nano bc kernel-devel epel-release kernel-modules-extra kernel-debug-modules-extra -y
$ yum install xz-lzma-compat rng-tools lvm2 iscsi-initiator-utils cifs-utils biosdevname nvme-cli plymouth cryptsetup lldpad mdadm nbd -y
```

Get the kernel sources for TCP BBRv3 from GitHub repository
```
$ git clone -o google-bbr -b v3  https://github.com/google/bbr.git
$ cd bbr
```

Create ssh key
```
$ ssh-keygen
$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
$ ssh localhost
$ exit
```

Merge Linux config to build the kernel. NOTE: this is needed to boot into the new kernel.
```
$ ls -la /boot/config-$(uname -r)
# In this case, my output is: /boot/config-4.18.0-477.21.1.el8_8.x86_64
$ cp /boot/config-4.18.0-477.21.1.el8_8.x86_64 ~/bbr/
```

Modify the `gce-install.sh` file to merge the Linux config with the TCP BBRv3
```
$ sed -i 's/INSTALL_MOD_PATH=${GCE_INSTALL_DIR}/INSTALL_MOD_PATH=${GCE_INSTALL_DIR} \\\n           INSTALL_MOD_STRIP=1/g' gce-install.sh
$ sed -i 's/cp config.gce .config/cp config-4.18.0-477.21.1.el8_8.x86_64 .config\nscripts\/kconfig\/merge_config.sh -m config.gce config-4.18.0-477.21.1.el8_8.x86_64/g' gce-install.sh
```

Modify the `config-4.18.0-477.21.1.el8_8.x86_64` file to set up some options for the kernel installation
```
$ sed -i 's/CONFIG_SYSTEM_TRUSTED_KEYS="certs\/rhel.pem"/CONFIG_SYSTEM_TRUSTED_KEYS=""/g' config-4.18.0-477.21.1.el8_8.x86_64
$ sed -i 's/CONFIG_SYSTEM_REVOCATION_KEYS="debian\/canonical-revoked-certs.pem"/CONFIG_SYSTEM_REVOCATION_KEYS=""/g' config-4.18.0-477.21.1.el8_8.x86_64
$ sed -i 's/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g' config-4.18.0-477.21.1.el8_8.x86_64
$ sed -i 's/CONFIG_DEBUG_INFO_BTF_MODULES=y/CONFIG_DEBUG_INFO_BTF_MODULES=n/g' config-4.18.0-477.21.1.el8_8.x86_64
```

Build the kernel
```
$ ./gce-install.sh -m localhost
# Wait until the end. The VM will automatically reboot. It takes some time...
```

Compile the kernel
```
$ tar --no-same-owner -xzvf kernel-+v3+6e321d1c986a+GCE.tar.gz2 -C /
$ depmod -a 6.4.0+v3+6e321d1c986a+GCE
$ dracut -f -v --hostonly -k '/lib/modules/6.4.0+v3+6e321d1c986a+GCE' /boot/initramfs-6.4.0+v3+6e321d1c986a+GCE.img 6.4.0+v3+6e321d1c986a+GCE
```

Set the kernel as the default one and reboot the machine
```
$ grubby --grub2 --add-kernel=/boot/vmlinuz-6.4.0+v3+6e321d1c986a+GCE --title="Linux BBRv3" --initrd=/boot/initramfs-6.4.0+v3+6e321d1c986a+GCE.img --copy-default
$ grubby --set-default /boot/vmlinuz-6.4.0+v3+6e321d1c986a+GCE
$ grubby --default-kernel
$ grubby --info=ALL
$ reboot
```

Verify the successful kernel installation
```
$ uname -a
# You should see the branch name SHA1 hash, and build time stamp from the kernel you built above.
# Linux bbrv3-vm.cern.ch 6.4.0+v3+6e321d1c986a+GCE #1 SMP PREEMPT_DYNAMIC Tue Oct  3 17:18:46 CEST 2023 x86_64 x86_64 x86_64 GNU/Linux
```

Enable BBRv3 in the kernel
```
$ modprobe tcp_dctcp
$ modprobe tcp_bbr
$ bash -c "echo 'tcp_dctcp' > /etc/modules-load.d/dctcp.conf"
$ bash -c "echo 'tcp_bbr' > /etc/modules-load.d/bbr.conf"
```

Verify that BBRv3 is enable in the kernel
```
$ sysctl net.ipv4.tcp_available_congestion_control
# Output: net.ipv4.tcp_available_congestion_control = reno bbr1 cubic dctcp bbr
```

Run `iperf3` with BBR pace at 6 Gb/s in both directions
```
$ iperf3 -C bbr --fq-rate 6G -c remote_host
```
