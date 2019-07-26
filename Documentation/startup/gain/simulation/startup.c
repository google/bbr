/* A simple discrete event simulation of BBR's behavior in STARTUP mode. */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#define max(a, b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b; })

/* Constants for a simulation: */
const int initial_cwnd = 10;	    /* Simulated initial cwnd in packets */
const double rtt_sec = .1;	    /* Simulation RTT in seconds */
const double bucket_sec = .000001;  /* Simulation time granularity in seconds */
const int sim_secs = 2.0;	    /* seconds to simulate */
int num_buckets = 0;		    /* Number of sim time buckets (derived) */

/* Command line args: */
double pacing_gain = 0.0; /* Simulated STARTUP pacing gain */

/* Run-time state for a simulation: */
struct bucket_info {		/* info for a given time bucket */
	int packets_acked;	/* packets acknowledged in this bucket */
	int round_trip;		/* round-trip epoch counter */
};
struct bucket_info *buckets;	/* array of all 'num_buckets' buckets */
double time_sec = 0.0;		/* current discrete event simulation time */
int round_trip = 0;		/* round-trip counter */
int bucket = 0;			/* index of current simulation bucket */
int cwnd = 0;			/* current cwnd in packets */
int packets_in_flight = 0;	/* current packets sent but unacked */
int packets_sent = 0;		/* total packets sent so far */
double last_tx = 0.0;		/* time of last paced transmit */
double estimated_bw = 0.0;	/* Estimated bandwidth in packets per sec */
double pacing_rate = 0.0;	/* Pacing rate in packets per sec */
double last_estimated_bw = -1;  /* est bw last round, to check growth */

/* Return the index of the bucket corresponding to the given simulation time. */
int secs_to_bucket(double secs)
{
	return secs / bucket_sec;
}

/* Calculate the next time the pacing engine will allow us to send. */
double next_pacing_release_time_secs(void)
{
	double delay_secs = 1.0 / pacing_rate;

	if (packets_sent < initial_cwnd)
		return 0.0;			/* initial burst */
	return last_tx + delay_secs;
}

/* Print a human-readable and awkable summary of our status. */
void debug_print(void)
{
	printf("t: %.6f round: %d "
	       "cwnd: %6d pif: %6d bw: %6f pacing_rate: %6f "
	       "release: %.6f\n",
	       time_sec, round_trip,
	       cwnd, packets_in_flight, estimated_bw, pacing_rate,
	       next_pacing_release_time_secs());
}

/* Will the pacing engine allow us to send? */
bool can_pace_more_packets_out(void)
{
	return time_sec >= next_pacing_release_time_secs();
}

/* Simulate the transmission of a packet. */
void send_packet(void)
{
	assert(packets_in_flight < cwnd);
	assert(can_pace_more_packets_out());
	packets_in_flight++;
	packets_sent++;
	last_tx = time_sec;
	/* Calculate when the packet will be ACKed, and record the time
	 * at which to simulate the arrival of the packet's ACK. Assumes
	 * pipe is not full yet.
	 */
	buckets[secs_to_bucket(time_sec + rtt_sec)].packets_acked++;
	buckets[secs_to_bucket(time_sec + rtt_sec)].round_trip = round_trip + 1;
}

/* Estimate bw as the number of packets delivered in last round trip.
 * Applies a simple max filter. Assumes the link is not saturated yet.
 */
void update_estimated_bw(void)
{
	int buckets_per_rtt = rtt_sec / bucket_sec;
	int b = 0, n = 0, packets_delivered = 0;
	double bw_sample = 0.0;

	for (b = bucket; b >= 0 && n < buckets_per_rtt; b--, n++)
		packets_delivered += buckets[b].packets_acked;
	bw_sample = packets_delivered / rtt_sec;
	estimated_bw = max(estimated_bw, bw_sample);
}

/* Update pacing rate. Assumes the link is not saturated yet. */
void update_pacing_rate(void)
{
	double rate = pacing_gain * estimated_bw;

	if (rate > pacing_rate)
		pacing_rate = rate;
}

/* Simulate an initial burst sent at time t=0, whose ACKs all arrive after
 * exactly one round trip time.
 */
void initial_burst(void)
{
	int i = 0;

	cwnd = initial_cwnd;
	packets_in_flight = 0;
	last_tx = 0.0;
	pacing_rate = pacing_gain * initial_cwnd / rtt_sec;
	for (i = 0; i < initial_cwnd; i++)
		send_packet();
	debug_print();
}

/* Print a summary of the growth of estimated bw per round trip. */
void check_bw_growth_rate(void)
{
	double bw_growth = -1;

	if (last_estimated_bw > 0)
		bw_growth = estimated_bw / last_estimated_bw;
	else
		bw_growth = 0.0;
	printf("ROUND: bw: %.3fx ", bw_growth);
	last_estimated_bw = estimated_bw;
}

/* We have moved into a new time bucket. Look at newly
 * delivered packets, update cwnd, estimated bw, pacing rate.
 */
void process_acks(void)
{
	int packets_acked = buckets[bucket].packets_acked;

	if (packets_acked == 0)
		return;

	if (buckets[bucket].round_trip > round_trip)
		check_bw_growth_rate();
	round_trip = buckets[bucket].round_trip;
	assert(packets_acked <= packets_in_flight);
	packets_in_flight -= packets_acked;
	update_estimated_bw();
	update_pacing_rate();
	cwnd += packets_acked;  /* slow-start cwnd upward */
}

/* Simulate the delivery and send process for BBR in STARTUP. */
void steady_state(void)
{
	while (bucket < num_buckets - 1) {
		double next_bucket_sec = 0.0, next_release_sec = 0.0;

		/* Advance to the sooner of:
		 * (a) the next packet send time
		 * (b) the next time bucket (when ACKs might arrive)
		 */
		next_bucket_sec = (bucket + 1) * bucket_sec;
		next_release_sec = max(time_sec,
				       next_pacing_release_time_secs());
		if (packets_in_flight < cwnd &&
		    next_release_sec < next_bucket_sec) {
			/* Next event is pacing engine releasing a packet. */
			time_sec = next_release_sec;
			send_packet();
		} else {
			/* Next event is moving to next bucket. */
			time_sec = next_bucket_sec;
			bucket++;
			process_acks();
		}
		debug_print();
	}
}

void simulate(void)
{
	initial_burst();
	steady_state();
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <pacing_gain>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	pacing_gain = atof(argv[1]);

	num_buckets = sim_secs / bucket_sec;  /* Number of sim time buckets */
	buckets = calloc(num_buckets, sizeof(buckets[0]));

	simulate();

	return 0;
}
