# BBR FAQ

Here are some frequently asked questions about BBR congestion control,
including Linux TCP BBR and QUIC BBR.

## Where can I discuss BBR?

Comments, questions, and discussion are welcome on the public bbr-dev mailing
list:

  https://groups.google.com/d/forum/bbr-dev

## Where can I read about BBR?

There are Google publications about BBR linked at the top of the bbr-dev
mailing list home page:

  https://groups.google.com/d/forum/bbr-dev


## Where can I find the source code for Linux TCP BBR?

For Linux TCP BBR:

- The latest code:
  - https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/tree/net/ipv4/tcp_bbr.c
- The list of commits:
  -  https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/log/net/ipv4/tcp_bbr.c

## How can I try out Linux TCP BBR?

Check out [TCP BBR Quick-Start: Building and Running TCP BBR on Google Compute Engine](https://github.com/google/bbr/blob/master/Documentation/bbr-quick-start.md).

## How can I test Linux TCP BBR with an emulated network?

For a feature-rich tool to test Linux TCP performance over emulated networks,
check out the [transperf](https://github.com/google/transperf) tool, which
handles the details of configuring network emulation on a single machine or
sets of physical machines.

If you want to manually configure an emulated network scenario on Linux
machines, you can use netem directly. However, keep in mind that TCP
performance results are not realistic when netem is installed on the sending
machine, due to interactions between netem and mechanisms like TSQ (TCP small
queues). To get realistic TCP performance results with netem, the netem qdisc
has to be installed either on an intermediate "router" machine or on the
ingress path of the receiving machine.

For examples on how to install netem on the ingress of a machine, see the ifb0
example in the "How can I use netem on incoming traffic?" section of the
[linuxfoundation.org netem page](https://wiki.linuxfoundation.org/networking/netem).

Another factor to consider is that when you emulate loss with netem, the netem
qdisc makes drop decisions in terms of entire ```sk_buff``` TSO bursts (of up
to 44 lMTU-sized packets), rather than individual MTU-sized packets. This makes
the loss process highly unrealistic relative to a drop process that drops X% of
MTU-size packets: the time in between drops can be up to 44x longer, and the
drops are much burstier (e.g. dropping 44 MTU-sized packets in a single
```sk_buff```). For more realistic loss processes you may need to disable LRO
and GRO.

## How can I visualize the behavior of Linux TCP BBR connections?

Check out [tcpdump](http://www.tcpdump.org/),
[tcptrace](http://www.tcptrace.org/), and
[xplot.org](http://www.xplot.org/). To install these tools on Ubuntu or Debian
you can use:

```
sudo apt-get install tcpdump tcptrace xplot-xplot.org
```

For an intro to this tool chain, see
[this slide deck](https://fasterdata.es.net/assets/Uploads/20131016-TCPDumpTracePlot.pdf).

An example session might look like:
```
# start capturing a trace:
tcpdump -w ./trace.pcap -s 120 -c 100000000 port $PORT &
# run test....
# turn trace into plot files:
tcptrace -S -zx -zy *pcap
# visualize each connection:
for f in `ls *xpl`; do echo $f ... ; xplot.org $f ; done
```

## How can I monitor Linux TCP BBR connections?

You can see output that includes BBR state variables, including pacing rate,
cwnd, bandwidth estimate, min_rtt estimate, etc., if you run:

```
ss -tin
```

If your machine does not have a recent enough version of ss to show those stats for BBR, you can download ss using the instructions here:
  https://wiki.linuxfoundation.org/networking/iproute2

Specifically, you can try something like:

```
git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git
cd iproute2/
./configure
make
```

Then you can run the tool as:
```
misc/ss -tin
```

And get output like the following:


```
  bbr wscale:8,7 rto:216 rtt:15.924/4.256 ato:40 mss:1348 pmtu:1500
  rcvmss:1208 advmss:1428 cwnd:16 bytes_acked:3744 bytes_received:8845
  segs_out:15 segs_in:16 data_segs_out:6 data_segs_in:13
  bbr:(bw:2.0Mbps,mrtt:14.451,pacing_gain:2.88672,cwnd_gain:2.88672)
  send 10.8Mbps lastsnd:8208 lastrcv:8188 lastack:8188
  pacing_rate 22.7Mbps delivery_rate 2.0Mbps app_limited
  busy:68ms rcv_rtt:18.349 rcv_space:28800 rcv_ssthresh:46964
  minrtt:14.451
```

## How can I programmatically get Linux TCP BBR congestion control state for a socket?

You can get key Linux TCP BBR state variables, including bandwidth estimate, min_rtt estimate, etc., using the TCP_CC_INFO socket option. For example:

```
#include <linux/inet_diag.h>
...
typedef unsigned long long u64;
...
  int fd;
  u64 bw;
 
  union tcp_cc_info info;
  socklen_t len = sizeof(info);

  if (getsockopt(fd, SOL_TCP, TCP_CC_INFO, &info, &len) < 0) {
    perror("getsockopt(TCP_CC_INFO)");
    exit(EXIT_FAILURE);
  }

  if (len >= sizeof(info.bbr)) {
    bw = ((u64)info.bbr.bbr_bw_hi << 32) | (u64)info.bbr.bbr_bw_lo;
    printf("bw: %lu bytes/sec\n", bw);
    printf("min_rtt: %u usec\n", info.bbr.bbr_min_rtt);
  }
```

## Where can I find the source code for QUIC BBR?

For QUIC BBR:

- The latest code:
  - https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr_sender.cc
  - https://github.com/google/quiche/blob/main/quiche/quic/core/congestion_control/bbr_sender.h

## How can I visualize the behavior of QUIC connections?

Check out [quic-trace](https://github.com/google/quic-trace).

## Where does the value of the BBR STARTUP pacing_gain come from?

In a nutshell, the BBR STARTUP pacing gain is derived to be the lowest gain that
will allow the pacing rate to double each round trip, when the pacing rate is
computed as a multiple of the maximum recent delivery rate seen.

Here is a detailed derivation, along with some graphs to illustrate:

- https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_startup_gain.pdf

## Where does the value of the BBR DRAIN pacing_gain come from?

In a nutshell, the BBR DRAIN pacing gain is derived to be the pacing gain that
is selected to try to drain the queue created by STARTUP in one packet-timed
round trip.

Here is a detailed derivation:

- https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_drain_gain.pdf

## How does BBR converge to an approximately fair share of bandwidth?

In short, when there are multiple BBR flows sharing a bottleneck
where there is no loss or ECN, BBR flows with a low share of throughput
grow their bandwidth measurements more quickly than flows with a high
share of throughput.

Here is a detailed discussion:

- https://github.com/google/bbr/blob/master/Documentation/bbr_bandwidth_based_convergence.pdf
