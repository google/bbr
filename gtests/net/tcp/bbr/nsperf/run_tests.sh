#!/bin/bash
#
# Run a set of tests with bbr1, bbr, cubic, dctcp.
# By default, runs all tests:
#   ./run_tests.sh
# But you can also run a subset of tests by setting the "tests"
# environment variable:
#   tests="coexist shallow" ./run_tests.sh
#

set -x

# By default run all tests.
# To run a subset of tests, set the environment variable: tests="foo bar".
if [ "$tests" = "" ]; then
    tests="coexist random_loss shallow bufferbloat ecn_bulk"
fi

# Make sure send and receive buffers can grow quite large. A BDP of 10Gbit/sec
# * 100ms is 125MBytes, so to tolerate high loss rates and lots of SACKed data,
# we allow autotuning to use 512MByte socket send and receive buffers:
MEM=$((512 * 1024 * 1024))
set +e
sysctl -w net.core.rmem_max=$MEM net.ipv4.tcp_rmem="4096 131072 $MEM"
sysctl -w net.core.wmem_max=$MEM net.ipv4.tcp_wmem="4096  16384 $MEM"
set -e

function get_buf_pkts() {
    buf_pkts=`echo | awk -v bw=$bw -v rtt=$rtt -v bdp_of_buf=$bdp_of_buf '{bdp_pkts = int(bw*1000*1000*rtt/1000.0 / (1514 * 8) * bdp_of_buf); print bdp_pkts;}'`
}

if [[ $tests == *"coexist"* ]]; then
    # show acceptable coexistence w/ cubic:
    # graph tput of 1 cubic, 1 bbr at a range of buffer depths:
    # (bw=50M, rtt=30ms, buf={...}xBDP)
    # [run for a very long time, 10minutes, to find convergence...]
    for cc_combo in cubic:1,bbr1:1 cubic:1,bbr:1; do
	for bdp_of_buf in  0.1  1 2 4 8 16; do
	    cmd=""
	    cc=$cc_combo     # mix of CCs in this experiment
	    interval=2       # interval between flow starts, in secs
	    bw=50            # Mbit/sec
	    rtt=30           # ms
	    qdisc=''         # use netem FIFO
	    loss=0           # loss in percent
	    dur=180          # test duration in secs
	    outdir="out/coexist/${cc}/$bdp_of_buf/"
	    # Create output directory:
	    mkdir -p $outdir
	    get_buf_pkts
	    set +e
	    cc=$cc bw=$bw rtt=$rtt buf=$buf_pkts qdisc=$qdisc loss=$loss \
	      dur=$dur cmd=$cmd outdir=$outdir interval=$interval \
	      ./nsperf.py stream | tee ${outdir}/nsperf.out.txt
	    set -e
	done
    done
fi

if [[ $tests == *"random_loss"* ]]; then
    # show high throughput with random loss up to design parameter:
    # graph tput of cubic, bbr at a range of random loss rates
    # (bw=1G, rtt=100ms, loss={....}
    for rep in `seq 1 10`; do
	for cc_name in cubic bbr1 bbr; do
	    loss_rates="0.00001 0.0001 0.001 0.01 0.1 0.2 0.5 1 2 3 10 15 20"
	    for loss_rate in $loss_rates; do
		cmd=""
		cc=${cc_name}:1  # 1 flow
		interval=0       # interval between flow starts, in secs
		bw=1000          # Mbit/sec
		rtt=100          # ms
		bdp_of_buf=1     # buffer = 100% of BDP, or 100ms
		qdisc=''         # use netem FIFO
		loss=$loss_rate  # loss in percent
		mem=$MEM         # bytes of netperf sock snd/rcv memory
		dur=60           # test duration in secs
		outdir="out/random_loss/${cc}/${loss}/rep-${rep}/"
		# Create output directory:
		mkdir -p $outdir
		get_buf_pkts
		set +e
		cc=$cc bw=$bw rtt=$rtt buf=$buf_pkts qdisc=$qdisc loss=$loss \
		  mem=$mem dur=$dur cmd=$cmd outdir=$outdir interval=$interval \
		  ./nsperf.py stream | tee ${outdir}/nsperf.out.txt
		set -e
	    done
	done
    done
fi

if [[ $tests == *"shallow"* ]]; then
    # show reasonably low loss rates in shallow buffers:
    # graph retransmit rate for range of flow counts
    # (bw=1G, rtt=100ms, buf=1ms, num_flows={...})
    # BDP is 1G*100ms = 8256 packets
    for cc_name in cubic bbr1 bbr; do
	for num_flows in 1 10 30 60 100; do
	    cmd=""
	    cc=${cc_name}:${num_flows}
	    interval=.139    # interval between flow starts, in secs
	    bw=1000          # Mbit/sec
	    rtt=100          # ms
	    bdp_of_buf=0.02  # buffer = 2% of BDP, or 2ms
	    qdisc=''         # use netem FIFO
	    loss=0           # loss in percent
	    dur=300          # test duration in secs
	    outdir="out/shallow/${cc}/${num_flows}/"
	    # Create output directory:
	    mkdir -p $outdir
	    get_buf_pkts
	    set +e
	    cc=$cc bw=$bw rtt=$rtt buf=$buf_pkts qdisc=$qdisc loss=$loss \
	      dur=$dur cmd=$cmd outdir=$outdir interval=$interval \
	      ./nsperf.py stream | tee ${outdir}/nsperf.out.txt
	    set -e
	done
    done
fi

if [[ $tests == *"bufferbloat"* ]]; then
    # show low delay in deep buffers, even without ECN signal:
    # graph p50 RTT for two flows using either cubic or bbr,
    # at a range of buffer depths.
    # (bw=50M, rtt=30ms, buf={...}xBDP)
    for cc_name in cubic bbr1 bbr; do
	for bdp_of_buf in 1 10 50 100; do
	    cmd=""
	    cc=${cc_name}:2  # 2 flows
	    interval=2       # interval between flow starts, in secs
	    bw=50            # Mbit/sec
	    rtt=30           # ms
	    qdisc=''         # use netem FIFO
	    loss=0           # loss in percent
	    dur=120          # test duration in secs
	    outdir="out/bufferbloat/${cc}/${bdp_of_buf}/"
	    # Create output directory:
	    mkdir -p $outdir
	    get_buf_pkts
	    set +e
	    cc=$cc bw=$bw rtt=$rtt buf=$buf_pkts qdisc=$qdisc loss=$loss \
	      dur=$dur cmd=$cmd outdir=$outdir interval=$interval \
	      ./nsperf.py stream | tee ${outdir}/nsperf.out.txt
	    set -e
	done
    done
fi


if [[ $tests == *"ecn_bulk"* ]]; then
    # show ECN support can keep queues very low:
    # graph p50 and p95 RTT (and retx, tput, fairness) for range of flow counts
    # (bw=1G, rtt=1ms, num_flows={...})
    for rep in `seq 1 10`; do
	for cc_name in bbr bbr1 dctcp; do
	    for num_flows in 1 4 10 40 100; do
		# Inside the child/test namespaces, enable ECN for
		# both active and passive connections:
		cmd='sysctl net.ipv4.tcp_ecn=1'
		cc=${cc_name}:${num_flows}
		interval=.005    # interval between flow starts, in secs
		bw=1000          # Mbit/sec
		rtt=1            # ms
		buf_pkts=0       # not using netem buffer
                # Enable "features ecn_low" on default route of server:
                ecn_low=1
		# We set the limit to 1000 packets, or 12ms at 1Gbit/sec.
		# We configure the target to be far higher, to disable
		# Codel-based drops.
		qdisc='codel ce_threshold 242us limit 1000 target 100ms'
		loss=0           # loss in percent
		dur=10           # test duration in secs
		outdir="out/ecn_bulk/${cc_name}/${num_flows}/rep-${rep}/"
		# Create output directory:
		mkdir -p $outdir
		get_buf_pkts
		set +e
		cc=$cc bw=$bw rtt=$rtt buf=$buf_pkts ecn_low=$ecn_low \
                  qdisc=$qdisc loss=$loss \
		  dur=$dur cmd=$cmd outdir=$outdir interval=$interval \
		  ./nsperf.py stream | tee ${outdir}/nsperf.out.txt
		set -e
	    done
	done
    done
fi

echo "done running all tests: $tests"
