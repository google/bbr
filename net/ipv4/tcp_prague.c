// SPDX-License-Identifier: GPL-2.0
/* TCP Prague congestion control.
 *
 * This congestion-control, part of the L4S architecture, achieves low loss,
 * low latency and scalable throughput when used in combination with AQMs such
 * as DualPI2, CurvyRED, or even fq_codel with a low ce_threshold for the
 * L4S flows.
 *
 * This is similar to DCTCP, albeit aimed to be used over the public
 * internet over paths supporting the L4S codepoint---ECT(1), and thus
 * implements the safety requirements listed in Appendix A of:
 * https://tools.ietf.org/html/draft-ietf-tsvwg-ecn-l4s-id-08#page-23
 *
 * Notable changes from DCTCP:
 *
 * 1/ RTT independence:
 * prague will operate in a given RTT region as if it was experiencing a target
 * RTT (default=10ms), while preserving the responsiveness it is able to
 * achieve due to its base RTT (i.e., quick reaction to sudden congestion
 * increase). This enable short RTT flows to co-exist with long RTT ones (e.g.,
 * intra-DC flows competing vs internet traffic) without causing starvation or
 * saturating the ECN signal, without the need for Diffserv/bandwdith
 * reservation.
 *
 * This is achieved by scaling cwnd growth during Additive Increase, thus
 * leaving room for higher RTT flows to grab a larger bandwidth share while at
 * the same time relieving the pressure on bottleneck link hence lowering the
 * overall marking probability.
 *
 * Given that this slows short RTT flows, this behavior only makes sense for
 * long-running flows that actually need to share the link--as opposed to,
 * e.g., RPC traffic. To that end, flows progressively become more RTT
 * independent as they grow "older".
 *
 * The different scaling heuristics enable to perform different tradeoffs, most
 * notabley between absolute rate fairness (e.g., RTT_CONTROL_RATE) and
 * scalability (e.g., RTT_CONTROL_SCALABLE aims to get at least 2 marks every
 * 8ish RTTs for flows with an e2e RTT < 100us, up to the classical 2 marks per
 * RTT for flows operating at the target RTT or above it).
 *
 *   TODO(otilmans)--#paper-ref.
 *
 * 2/ Updated EWMA:
 * The resolution of alpha has been increased to ensure that a low amount of
 * marks over high-BDP paths can be accurately taken into account in the
 * computation.
 *
 * Orthogonally, the value of alpha that is kept in the connection state is
 * stored upscaled, in order to preserve its remainder over the course of its
 * updates (similarly to how tp->srtt_us is maintained, as opposed to
 * dctcp->alpha).
 *
 * 3/ Updated cwnd management code
 * In order to operate with a permanent, (very) low, marking probability, the
 * arithmetic around cwnd has been updated to track its decimals alongside its
 * integer part. This both improve the precision, avoiding avalanche effects as
 * remainders are carried over the next operation, as well as responsiveness as
 * the AQM at the bottleneck can effectively control the operation of the flow
 * without drastic marking probability increase.
 *
 * Finally, when deriving the cwnd reduction from alpha, we ensure that the
 * computed value is unbiased wrt. integer rounding.
 *
 * 4/ Additive Increase uses unsaturated marking
 * Given that L4S AQM may induce randomly applied CE marks (e.g., from the PI2
 * part of dualpi2), instead of full RTTs of marks once in a while that a step
 * AQM would cause, cwnd is updated for every ACK, regardless of the congestion
 * status of the connection (i.e., it is expected to spent most of its time in
 * TCP_CA_CWR when used over dualpi2).
 *
 * To ensure that it can operate properly in environment where the marking level
 * is close to saturation, its increase also unsature the marking, i.e., the
 * total increase over a RTT is proportional to (1-p)/p.
 *
 * See https://arxiv.org/abs/1904.07605 for more details around saturation.
 *
 * 5/ Pacing/tso sizing
 * prague aims to keep queuing delay as low as possible. To that end, it is in
 * its best interest to pace outgoing segments (i.e., to smooth its traffic),
 * as well as impose a maximal GSO burst size to avoid instantaneous queue
 * buildups in the bottleneck link.
 */

#define pr_fmt(fmt) "TCP-Prague " fmt

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>

#define MIN_CWND		2U
#define PRAGUE_ALPHA_BITS	20U
#define PRAGUE_MAX_ALPHA	(1ULL << PRAGUE_ALPHA_BITS)
#define CWND_UNIT		20U
#define ONE_CWND		(1LL << CWND_UNIT) /* Must be signed */
#define PRAGUE_SHIFT_G		4		/* EWMA gain g = 1/2^4 */
#define DEFAULT_RTT_TRANSITION	500
#define MAX_SCALED_RTT		(100 * USEC_PER_MSEC)
#define RTT_UNIT		7
#define RTT2US(x)		((x) << RTT_UNIT)
#define US2RTT(x)		((x) >> RTT_UNIT)

#define PRAGUE_MAX_SRTT_BITS	18U
#define PRAGUE_MAX_MDEV_BITS	(PRAGUE_MAX_SRTT_BITS+1)
#define PRAGUE_INIT_MDEV_CARRY	741455 /* 1 << (PRAGUE_MAX_MDEV_BITS+0.5) */
#define PRAGUE_INIT_ADJ_US	262144 /* 1 << (PRAGUE_MAX_MDEV_BITS-1) */

/* Weights, 1/2^x */
#define V 1	/* 0.5 */
#define D 1	/* 0.5 */
#define S 2	/* 0.25 */

/* Store classic_ecn with same scaling as alpha */
#define L_STICKY	(16ULL << (PRAGUE_ALPHA_BITS-V))	/* Pure L4S behaviour */
#define CLASSIC_ECN L_STICKY + \
	PRAGUE_MAX_ALPHA		/* Transition between classic and L4S */
#define C_STICKY	CLASSIC_ECN + \
	L_STICKY			/* Pure classic behaviour */

#define V0_LG	(10014683ULL >> V)	/* reference queue V of ~750us */
#define D0_LG	(11498458ULL >> D)	/* reference queue D of ~2ms */

/* RTT cwnd scaling heuristics */
enum {
	/* No RTT independence */
	RTT_CONTROL_NONE = 0,
	/* Flows with e2e RTT <= target RTT achieve the same throughput */
	RTT_CONTROL_RATE,
	/* Trade some throughput balance at very low RTTs for a floor on the
	 * amount of marks/RTT */
	RTT_CONTROL_SCALABLE,
	/* Behave as a flow operating with an extra target RTT */
	RTT_CONTROL_ADDITIVE,

	__RTT_CONTROL_MAX
};

static u32 prague_burst_shift __read_mostly = 12; /* 1/2^12 sec ~=.25ms */
MODULE_PARM_DESC(prague_burst_shift,
		 "maximal GSO burst duration as a base-2 negative exponent");
module_param(prague_burst_shift, uint, 0644);

static u32 prague_max_tso_segs __read_mostly = 0;
MODULE_PARM_DESC(prague_max_tso_segs, "Maximum TSO/GSO segments");
module_param(prague_max_tso_segs, uint, 0644);

static u32 prague_rtt_scaling __read_mostly = RTT_CONTROL_RATE;
MODULE_PARM_DESC(prague_rtt_scaling, "Enable RTT independence through the "
		 "chosen RTT scaling heuristic");
module_param(prague_rtt_scaling, uint, 0644);

static u32 prague_rtt_target __read_mostly = 25 * USEC_PER_MSEC;
MODULE_PARM_DESC(prague_rtt_target, "RTT scaling target");
module_param(prague_rtt_target, uint, 0644);

static int prague_rtt_transition __read_mostly = DEFAULT_RTT_TRANSITION;
MODULE_PARM_DESC(prague_rtt_transition, "Amount of post-SS rounds to transition"
		 " to be RTT independent.");
module_param(prague_rtt_transition, uint, 0644);

static int prague_ecn_fallback __read_mostly = 0;
MODULE_PARM_DESC(prague_ecn_fallback, "0 = none, 1 = detection & fallback"
		" 2 = detection");
module_param(prague_ecn_fallback, int, 0644);

struct prague {
	u64 cwr_stamp;
	u64 alpha_stamp;	/* EWMA update timestamp */
	u64 upscaled_alpha;	/* Congestion-estimate EWMA */
	u64 ai_ack_increase;	/* AI increase per non-CE ACKed MSS */
	s64 cwnd_cnt;		/* cwnd update carry */
	s64 loss_cwnd_cnt;
	u32 loss_cwnd;
	u32 max_tso_burst;
	u32 rest_depth_us;
	u32 rest_mdev_us;
	u32 old_delivered;	/* tp->delivered at round start */
	u32 old_delivered_ce;	/* tp->delivered_ce at round start */
	u32 next_seq;		/* tp->snd_nxt at round start */
	u32 round;		/* Round count since last slow-start exit */
	u32 rtt_transition_delay;
	u32 rtt_target;		/* RTT scaling target */
	u8  saw_ce:1,		/* Is there an AQM on the path? */
	    rtt_indep:3,	/* RTT independence mode */
	    in_loss:1;		/* In cwnd reduction caused by loss */
};

struct rtt_scaling_ops {
	bool (*should_update_ewma)(struct sock *sk);
	u64 (*ai_ack_increase)(struct sock *sk, u32 rtt);
	u32 (*target_rtt)(struct sock *sk);
};
static struct rtt_scaling_ops rtt_scaling_heuristics[__RTT_CONTROL_MAX];

/* Fallback struct ops if we fail to negotiate AccECN */
static struct tcp_congestion_ops prague_reno;

static void __prague_connection_id(struct sock *sk, char *str, size_t len)
{
	u16 dport = ntohs(inet_sk(sk)->inet_dport);
	u16 sport = ntohs(inet_sk(sk)->inet_sport);

	if (sk->sk_family == AF_INET)
		snprintf(str, len, "%pI4:%u-%pI4:%u", &sk->sk_rcv_saddr, sport,
			&sk->sk_daddr, dport);
	else if (sk->sk_family == AF_INET6)
		snprintf(str, len, "[%pI6c]:%u-[%pI6c]:%u",
			 &sk->sk_v6_rcv_saddr, sport, &sk->sk_v6_daddr, dport);
}
#define LOG(sk, fmt, ...) do {						\
	char __tmp[2 * (INET6_ADDRSTRLEN + 9) + 1] = {0};		\
	__prague_connection_id(sk, __tmp, sizeof(__tmp));		\
	/* pr_fmt expects the connection ID*/				\
	pr_info("(%s) : " fmt "\n", __tmp, ##__VA_ARGS__);			\
} while (0)

static struct prague *prague_ca(struct sock *sk)
{
	return (struct prague*)inet_csk_ca(sk);
}

static bool prague_is_rtt_indep(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);

	return ca->rtt_indep != RTT_CONTROL_NONE &&
		!tcp_in_slow_start(tcp_sk(sk)) &&
		ca->round >= ca->rtt_transition_delay;
}

static struct rtt_scaling_ops* prague_rtt_scaling_ops(struct sock *sk)
{
	return &rtt_scaling_heuristics[prague_ca(sk)->rtt_indep];
}

static bool prague_e2e_rtt_elapsed(struct sock *sk)
{
	return !before(tcp_sk(sk)->snd_una, prague_ca(sk)->next_seq);
}

/* RTT independence on a step AQM requires the competing flows to converge to
 * the same alpha, i.e., the EWMA update frequency might no longer be "once
 * every RTT" */
static bool prague_should_update_ewma(struct sock *sk)
{
	return prague_e2e_rtt_elapsed(sk) &&
		(!prague_rtt_scaling_ops(sk)->should_update_ewma ||
		 !prague_is_rtt_indep(sk) ||
		 prague_rtt_scaling_ops(sk)->should_update_ewma(sk));
}

static u32 prague_target_rtt(struct sock *sk)
{
	return prague_rtt_scaling_ops(sk)->target_rtt ?
		prague_rtt_scaling_ops(sk)->target_rtt(sk) :
		prague_ca(sk)->rtt_target;
}

static u64 prague_unscaled_ai_ack_increase(struct sock *sk)
{
	return 1 << CWND_UNIT;
}

/* RTT independence will scale the classical 1/W per ACK increase. */
static void prague_ai_ack_increase(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	u64 increase;
	u32 rtt;

	if (!prague_rtt_scaling_ops(sk)->ai_ack_increase) {
		increase = prague_unscaled_ai_ack_increase(sk);
		goto exit;
	}

	rtt = US2RTT(tcp_sk(sk)->srtt_us >> 3);
	if (ca->round < ca->rtt_transition_delay ||
	    !rtt || rtt > MAX_SCALED_RTT) {
		increase = prague_unscaled_ai_ack_increase(sk);
		goto exit;
	}

	increase = prague_rtt_scaling_ops(sk)->ai_ack_increase(sk, rtt);

exit:
	WRITE_ONCE(ca->ai_ack_increase, increase);
}

/* Ensure prague sends traffic as smoothly as possible:
 * - Pacing is set to 100% during AI
 * - The max GSO burst size is bounded in time at the pacing rate.
 *
 *   We keep the 200% pacing rate during SS, as we need to send 2 MSS back to
 *   back for every received ACK.
 */
static void prague_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 max_inflight;
	u64 rate, burst;
	int mtu;

	mtu = tcp_mss_to_mtu(sk, tp->mss_cache);
	// Must also set tcp_ecn_option=0 and tcp_ecn_unsafe_cep=1
	// to disable the option and safer heuristic...
	max_inflight = max(tp->snd_cwnd, tcp_packets_in_flight(tp));

	rate = (u64)((u64)USEC_PER_SEC << 3) * mtu;
	if (tp->snd_cwnd < tp->snd_ssthresh / 2)
		rate <<= 1;
	if (likely(tp->srtt_us))
		rate = div64_u64(rate, tp->srtt_us);
	rate *= max_inflight;
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	/* TODO(otilmans) rewrite the tso_segs hook to bytes to avoid this
	 * division. It will somehow need to be able to take hdr sizes into
	 * account */
	burst = div_u64(rate, tcp_mss_to_mtu(sk, tp->mss_cache));

	WRITE_ONCE(prague_ca(sk)->max_tso_burst,
		   max_t(u32, 1, burst >> prague_burst_shift));
	WRITE_ONCE(sk->sk_pacing_rate, rate);
}

static void prague_new_round(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->next_seq = tp->snd_nxt;
	ca->old_delivered_ce = tp->delivered_ce;
	ca->old_delivered = tp->delivered;
	if (!tcp_in_slow_start(tp)) {
		++ca->round;
		if (!ca->round)
			ca->round = ca->rtt_transition_delay;
	}
	prague_ai_ack_increase(sk);
}

static void prague_cwnd_changed(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->snd_cwnd_stamp = tcp_jiffies32;
	prague_ai_ack_increase(sk);
}

/* TODO(asadsa): move this detection out of prague to make it more generic. */
/* TODO(asadsa): check if self-limited works as given out in the design */
static void prague_classic_ecn_detection(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 min_rtt_us = tcp_min_rtt(tp);
	u32 g_srtt_shift = tp->g_srtt_shift;
	u32 g_mdev_shift = tp->g_mdev_shift;
	u64 srtt_us = tp->srtt_pace_us >> g_srtt_shift;
	u64 mdev_us = tp->mdev_pace_us >> g_mdev_shift;
	u64 depth_us;
	u32 mdev_lg, depth_lg;
	u32 adj_us = PRAGUE_INIT_ADJ_US >> (PRAGUE_MAX_MDEV_BITS - g_mdev_shift);
	s64 new_classic_ecn = (s64)tp->classic_ecn;

	if (unlikely(!srtt_us) || unlikely(min_rtt_us == ~0U))
		return;

	/* Multiply upscaled mdev by upscaled geometric carry from the previous round
	 *  adding upscaled adjustment to unbias the subsequent integer log
	 */
	mdev_us = (u64)mdev_us * ca->rest_mdev_us + adj_us;
	mdev_lg = max_t(u32, ilog2(mdev_us), g_mdev_shift) - g_mdev_shift;
	/* carry the new rest to the next round */
	ca->rest_mdev_us = mdev_us >> mdev_lg;
	/* V*lg(mdev_us/VO) */
	mdev_lg <<= PRAGUE_ALPHA_BITS - V;
	new_classic_ecn += (s64)mdev_lg - V0_LG;

	if (unlikely(srtt_us <= min_rtt_us))
		goto out;

	depth_us = (srtt_us - min_rtt_us) * ca->rest_depth_us + (adj_us >> 1);
	depth_lg = max_t(u32, ilog2(depth_us), g_srtt_shift) - g_srtt_shift;
	ca->rest_depth_us = depth_us >> depth_lg;
	/* queue build-up can only bring classic_ecn toward more classic */
	/* + D*lg(max(d/D0, 1)) */
	depth_lg <<= PRAGUE_ALPHA_BITS - D;
	if (depth_lg > D0_LG) {
		new_classic_ecn += (u64)depth_lg - D0_LG;
	}

	/* self-limited? */
	//if (!tcp_is_cwnd_limited(sk))
	//	/* - S*s */
	//	new_classic_ecn -= PRAGUE_MAX_ALPHA -
	//	(tp->snd_cwnd_used << (PRAGUE_ALPHA_BITS-S)) / tp->snd_cwnd;

out:
	tp->classic_ecn = min_t(u64, max_t(s64, new_classic_ecn, 0), C_STICKY);
}

static void prague_update_alpha(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 ecn_segs, alpha;

	/* Do not update alpha before we have proof that there's an AQM on
	 * the path.
	 */
	if (unlikely(!ca->saw_ce))
		goto skip;

	if (prague_ecn_fallback > 0)
		prague_classic_ecn_detection(sk);

	alpha = ca->upscaled_alpha;
	ecn_segs = tp->delivered_ce - ca->old_delivered_ce;
	/* We diverge from the original EWMA, i.e.,
	 * alpha = (1 - g) * alpha + g * F
	 * by working with (and storing)
	 * upscaled_alpha = alpha * (1/g) [recall that 0<g<1]
	 *
	 * This enables to carry alpha's residual value to the next EWMA round.
	 *
	 * We first compute F, the fraction of ecn segments.
	 */
	if (ecn_segs) {
		u32 acked_segs = tp->delivered - ca->old_delivered;

		ecn_segs <<= PRAGUE_ALPHA_BITS;
		ecn_segs = div_u64(ecn_segs, max(1U, acked_segs));
	}
	alpha = alpha - (alpha >> PRAGUE_SHIFT_G) + ecn_segs;
	ca->alpha_stamp = tp->tcp_mstamp;
	alpha = min(PRAGUE_MAX_ALPHA << PRAGUE_SHIFT_G, alpha);

	WRITE_ONCE(ca->upscaled_alpha, alpha);
	tp->alpha = alpha >> PRAGUE_SHIFT_G;

skip:
	prague_new_round(sk);
}

static void prague_update_cwnd(struct sock *sk, const struct rate_sample *rs)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 increase;
	s64 acked;

	acked = rs->acked_sacked;
	if (rs->ece_delta) {
		if (rs->ece_delta > acked)
			LOG(sk, "Received %u marks for %lld acks at %u",
			    rs->ece_delta, acked, tp->snd_una);
		ca->saw_ce = 1;
		acked -= rs->ece_delta;
	}

	if (acked <= 0 || ca->in_loss || !tcp_is_cwnd_limited(sk))
		goto adjust;

	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked) {
			prague_cwnd_changed(sk);
			return;
		}
	}

	increase = acked * ca->ai_ack_increase;
	if (likely(tp->snd_cwnd))
		increase = div_u64(increase + (tp->snd_cwnd >> 1),
				   tp->snd_cwnd);
	ca->cwnd_cnt += max_t(u64, acked, increase);

adjust:
	if (ca->cwnd_cnt <= -ONE_CWND) {
		ca->cwnd_cnt += ONE_CWND;
		--tp->snd_cwnd;
		if (tp->snd_cwnd < MIN_CWND) {
			tp->snd_cwnd = MIN_CWND;
			/* No point in applying further reductions */
			ca->cwnd_cnt = 0;
		}
		tp->snd_ssthresh = tp->snd_cwnd;
		prague_cwnd_changed(sk);
	} else if (ca->cwnd_cnt >= ONE_CWND) {
		ca->cwnd_cnt -= ONE_CWND;
		++tp->snd_cwnd;
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
		prague_cwnd_changed(sk);
	}
	return;
}

static void prague_ca_open(struct sock *sk)
{
	prague_ca(sk)->in_loss = 0;
}

static void prague_enter_loss(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	ca->loss_cwnd_cnt = ca->cwnd_cnt;
	ca->cwnd_cnt -=
		(((u64)tp->snd_cwnd) << (CWND_UNIT - 1)) + (ca->cwnd_cnt >> 1);
	ca->in_loss = 1;
	prague_cwnd_changed(sk);
}

static void prague_update_rtt_scaling(struct sock *sk, u32 ssthresh)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int delta_shift;
	u8 new_g_srtt_shift;
	u8 old_g_srtt_shift = tp->g_srtt_shift;

	new_g_srtt_shift = ilog2(ssthresh);
	new_g_srtt_shift += (new_g_srtt_shift >> 1) + 1;
	tp->g_srtt_shift = min_t(u8, new_g_srtt_shift, PRAGUE_MAX_SRTT_BITS);
	tp->g_mdev_shift = tp->g_srtt_shift + 1;
	delta_shift = tp->g_srtt_shift - old_g_srtt_shift;

	if (!delta_shift)
		return;

	if (delta_shift > 0) {
		tp->srtt_pace_us <<= delta_shift;
		tp->mdev_pace_us <<= delta_shift;
		ca->rest_depth_us <<= delta_shift;
		ca->rest_mdev_us <<= delta_shift;
	} else {
		delta_shift = -delta_shift;
		tp->srtt_pace_us >>= delta_shift;
		tp->mdev_pace_us >>= delta_shift;
		ca->rest_depth_us >>= delta_shift;
		ca->rest_mdev_us >>= delta_shift;
	}
}

static u64 prague_classic_ecn_fallback(struct tcp_sock *tp, u64 alpha)
{
	u64 c = min(tp->classic_ecn, CLASSIC_ECN) - L_STICKY;
	/* 0 ... CLASSIC_ECN/PRAGUE_MAX_ALPHA */
	c = (c >> 1) + (c >> 3); /* c * ~0.6 */


	/* clamp alpha no lower than c to compete fair with classic AQMs */
	return max(alpha, c);
}

static void prague_enter_cwr(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 reduction;
	u64 alpha;

	if (prague_is_rtt_indep(sk) &&
	    RTT2US(prague_target_rtt(sk)) > tcp_stamp_us_delta(tp->tcp_mstamp,
							       ca->cwr_stamp))
		return;
	ca->cwr_stamp = tp->tcp_mstamp;
	alpha = ca->upscaled_alpha >> PRAGUE_SHIFT_G;

	if (prague_ecn_fallback == 1 && tp->classic_ecn > L_STICKY)
		alpha = prague_classic_ecn_fallback(tp, alpha);

	reduction = (alpha * ((u64)tp->snd_cwnd << CWND_UNIT) +
			 /* Unbias the rounding by adding 1/2 */
			 PRAGUE_MAX_ALPHA) >>
		(PRAGUE_ALPHA_BITS + 1U);
	ca->cwnd_cnt -= reduction;

	return;
}

/* Calculate SRTT & SMDEV with lower gain to see past instantaneous variation.
 * Also use accurate RTT measurement of last segment to do Classic ECN detection
 * rather than using RFC6298 which includes delay accumulated between two
 * successive segments at the receiver. Finally, we do not use this MDEV for RTO
 * so initialize it to zero. We use a tweaked version of tcp_rtt_estimator().
 */
static void prague_rtt_estimator(struct sock *sk, long mrtt_us)
{
	struct tcp_sock *tp = tcp_sk(sk);
	long long m = mrtt_us; /* Accurate RTT */
	u64 srtt_pace = tp->srtt_pace_us;
	tp->mrtt_pace_us = mrtt_us;

	if (srtt_pace != 0) {
		m -= (srtt_pace >> tp->g_srtt_shift);	/* m is now error in rtt est */
		srtt_pace += m;		/* rtt += 1/2^g_srtt_shift new */
		if (m < 0)
			m = -m;		/* m is now abs(error) */
		m -= (tp->mdev_pace_us >> tp->g_mdev_shift);
		tp->mdev_pace_us += m;		/* mdev += 1/2^g_mev_shift new */
	} else {
		/* no previous measure. */
		srtt_pace = m << tp->g_srtt_shift;	/* take the measured time to be rtt */
		tp->mdev_pace_us = 1ULL << tp->g_mdev_shift;
	}
	tp->srtt_pace_us = max(1ULL, srtt_pace);
}

static void prague_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	if (sample->rtt_us != -1)
		prague_rtt_estimator(sk, sample->rtt_us);
}

static void prague_state(struct sock *sk, u8 new_state)
{
	if (new_state == inet_csk(sk)->icsk_ca_state)
		return;

	switch (new_state) {
	case TCP_CA_Recovery:
		prague_enter_loss(sk);
		break;
	case TCP_CA_CWR:
		prague_enter_cwr(sk);
		break;
	case TCP_CA_Open:
		prague_ca_open(sk);
		break;
	}
}

static void prague_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	if (ev == CA_EVENT_LOSS)
		prague_enter_loss(sk);
}

static u32 prague_cwnd_undo(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);

	/* We may have made some progress since then, account for it. */
	ca->cwnd_cnt += ca->cwnd_cnt - ca->loss_cwnd_cnt;
	return max(ca->loss_cwnd, tcp_sk(sk)->snd_cwnd);
}

static void prague_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	prague_update_cwnd(sk, rs);
	if (prague_should_update_ewma(sk))
		prague_update_alpha(sk);
	prague_update_pacing_rate(sk);
}

static u32 prague_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	prague_update_rtt_scaling(sk, tp->snd_ssthresh);
	return tp->snd_ssthresh;
}

static u32 prague_tso_segs(struct sock *sk, unsigned int mss_now)
{
	u32 tso_segs = max_t(u32, prague_ca(sk)->max_tso_burst,
			     sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs);

	if (prague_max_tso_segs)
		tso_segs = min(tso_segs, prague_max_tso_segs);

	return tso_segs;
}

static size_t prague_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct prague *ca = prague_ca(sk);

	if (ext & (1 << (INET_DIAG_PRAGUEINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->prague, 0, sizeof(info->prague));
		if (inet_csk(sk)->icsk_ca_ops != &prague_reno) {
			info->prague.prague_alpha =
				ca->upscaled_alpha >> PRAGUE_SHIFT_G;
			info->prague.prague_max_burst = ca->max_tso_burst;
			info->prague.prague_ai_ack_increase =
				READ_ONCE(ca->ai_ack_increase);
			info->prague.prague_round = ca->round;
			info->prague.prague_rtt_transition =
				ca->rtt_transition_delay;
			info->prague.prague_enabled = 1;
			info->prague.prague_rtt_indep = ca->rtt_indep;
			info->prague.prague_rtt_target =
				prague_target_rtt(sk);
		}
		*attr = INET_DIAG_PRAGUEINFO;
		return sizeof(info->prague);
	}
	return 0;
}

static void prague_release(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NEEDED, SK_PACING_NONE);
	tp->ecn_flags &= ~TCP_ECN_ECT_1;
	if (!tcp_ecn_mode_any(tp))
		/* We forced the use of ECN, but failed to negotiate it */
		INET_ECN_dontxmit(sk);

	LOG(sk, "Released [delivered_ce=%u,received_ce=%u]",
	    tp->delivered_ce, tp->received_ce);
}

static void prague_init(struct sock *sk)
{
	struct prague *ca = prague_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_ecn_mode_any(tp) &&
	    sk->sk_state != TCP_LISTEN && sk->sk_state != TCP_CLOSE) {
		prague_release(sk);
		LOG(sk, "Switching to pure reno [ecn_status=%u,sk_state=%u]",
		    tcp_ecn_mode_any(tp), sk->sk_state);
		inet_csk(sk)->icsk_ca_ops = &prague_reno;
		return;
	}

	tp->ecn_flags |= TCP_ECN_ECT_1;
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	/* If we have an initial RTT estimate, ensure we have an initial pacing
	 * rate to use if net.ipv4.tcp_pace_iw is set.
	 */
	if (tp->srtt_us)
		prague_update_pacing_rate(sk);

	ca->alpha_stamp = tp->tcp_mstamp;
	ca->upscaled_alpha = PRAGUE_MAX_ALPHA << PRAGUE_SHIFT_G;
	ca->cwnd_cnt = 0;
	ca->loss_cwnd_cnt = 0;
	ca->loss_cwnd = 0;
	ca->max_tso_burst = 1;
	ca->round = 0;
	ca->rtt_transition_delay = prague_rtt_transition;
	ca->rtt_target = US2RTT(prague_rtt_target);
	ca->rtt_indep = ca->rtt_target ? prague_rtt_scaling : RTT_CONTROL_NONE;
	if (ca->rtt_indep >= __RTT_CONTROL_MAX)
		ca->rtt_indep = RTT_CONTROL_NONE;
	LOG(sk, "RTT indep chosen: %d (after %u rounds), targetting %u usec",
	    ca->rtt_indep, ca->rtt_transition_delay, prague_target_rtt(sk));
	ca->saw_ce = !!tp->delivered_ce;

	/* reuse existing meaurement of SRTT as an intial starting point */
	tp->g_srtt_shift = PRAGUE_MAX_SRTT_BITS;
	tp->g_mdev_shift = PRAGUE_MAX_MDEV_BITS;
	tp->mrtt_pace_us = tp->srtt_us >> 3;
	tp->srtt_pace_us = (u64)tp->mrtt_pace_us << tp->g_srtt_shift;
	tp->mdev_pace_us = 1ULL << tp->g_mdev_shift;
	ca->rest_mdev_us = PRAGUE_INIT_MDEV_CARRY;
	ca->rest_depth_us = PRAGUE_INIT_MDEV_CARRY >> 1;

	tp->classic_ecn = 0ULL;
	tp->alpha = PRAGUE_MAX_ALPHA;		/* Used ONLY to log alpha */

	prague_new_round(sk);
}

static bool prague_target_rtt_elapsed(struct sock *sk)
{
	return RTT2US(prague_target_rtt(sk)) <=
		tcp_stamp_us_delta(tcp_sk(sk)->tcp_mstamp,
				   prague_ca(sk)->alpha_stamp);
}

static u64 prague_rate_scaled_ai_ack_increase(struct sock *sk, u32 rtt)
{
	u64 increase;
	u64 divisor;
	u64 target;


	target = prague_target_rtt(sk);
	if (rtt >= target)
		return prague_unscaled_ai_ack_increase(sk);
	/* Scale increase to:
	 * - Grow by 1MSS/target RTT
	 * - Take into account the rate ratio of doing cwnd += 1MSS
	 *
	 * Overflows if e2e RTT is > 100ms, hence the cap
	 */
	increase = (u64)rtt << CWND_UNIT;
	increase *= rtt;
	divisor = target * target;
	increase = div64_u64(increase + (divisor >> 1), divisor);
	return increase;
}

static u64 prague_scalable_ai_ack_increase(struct sock *sk, u32 rtt)
{
	/* R0 ~= 16ms, R1 ~= 1.5ms */
	const s64 R0 = US2RTT(1 << 14), R1 = US2RTT((1 << 10) + (1 << 9));
	u64 increase;
	u64 divisor;

	/* Scale increase to:
	 * - Ensure a growth of at least 1/8th, i.e., one mark every 8 RTT.
	 * - Take into account the rate ratio of doing cwnd += 1MSS
	 */
	increase = (ONE_CWND >> 3) * R0;
	increase += ONE_CWND * min_t(s64, max_t(s64, rtt - R1, 0), R0);
	increase *= rtt;
	divisor = R0 * R0;
	increase = div64_u64(increase + (divisor >> 1), divisor);
	return increase;
}

static u32 prague_dynamic_rtt_target(struct sock *sk)
{
	return prague_ca(sk)->rtt_target + US2RTT(tcp_sk(sk)->srtt_us >> 3);
}

static struct rtt_scaling_ops
rtt_scaling_heuristics[__RTT_CONTROL_MAX] __read_mostly = {
	[RTT_CONTROL_NONE] = {
		.should_update_ewma = NULL,
		.ai_ack_increase = NULL,
		.target_rtt = NULL,
	},
	[RTT_CONTROL_RATE] = {
		.should_update_ewma = prague_target_rtt_elapsed,
		.ai_ack_increase = prague_rate_scaled_ai_ack_increase,
		.target_rtt = NULL,
	},
	[RTT_CONTROL_SCALABLE] = {
		.should_update_ewma = prague_target_rtt_elapsed,
		.ai_ack_increase = prague_scalable_ai_ack_increase,
		.target_rtt = NULL,
	},
	[RTT_CONTROL_ADDITIVE] = {
		.should_update_ewma = prague_target_rtt_elapsed,
		.ai_ack_increase = prague_rate_scaled_ai_ack_increase,
		.target_rtt = prague_dynamic_rtt_target
	},
};

static struct tcp_congestion_ops prague __read_mostly = {
	.init		= prague_init,
	.release	= prague_release,
	.cong_control	= prague_cong_control,
	.cwnd_event	= prague_cwnd_event,
	.ssthresh	= prague_ssthresh,
	.undo_cwnd	= prague_cwnd_undo,
	.pkts_acked	= prague_pkts_acked,
	.set_state	= prague_state,
	.get_info	= prague_get_info,
	.tso_segs	= prague_tso_segs,
	.flags		= TCP_CONG_NEEDS_ECN | TCP_CONG_NEEDS_ACCECN |
		TCP_CONG_NON_RESTRICTED,
	.owner		= THIS_MODULE,
	.name		= "prague",
};

static struct tcp_congestion_ops prague_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= prague_get_info,
	.owner		= THIS_MODULE,
	.name		= "prague-reno",
};

static int __init prague_register(void)
{
	BUILD_BUG_ON(sizeof(struct prague) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&prague);
}

static void __exit prague_unregister(void)
{
	tcp_unregister_congestion_control(&prague);
}

module_init(prague_register);
module_exit(prague_unregister);

MODULE_AUTHOR("Olivier Tilmans <olivier.tilmans@nokia-bell-labs.com>");
MODULE_AUTHOR("Koen De Schepper <koen.de_schepper@nokia-bell-labs.com>");
MODULE_AUTHOR("Bob briscoe <research@bobbriscoe.net>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("TCP Prague");
MODULE_VERSION("0.6");
