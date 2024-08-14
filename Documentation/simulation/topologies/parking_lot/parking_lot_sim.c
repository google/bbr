// A simple abstract simulator for parking-lot topology for BBR.
//
// See:
//  https://groups.google.com/g/bbr-dev/c/lHYHY_P9DsU/m/_O6f4OLjBAAJ

#include <stdio.h>

#define BW_CYCLE_LEN 8
const double pacing_gain_cycle[BW_CYCLE_LEN] = {
  1.25,
  0.9,
  1.0,
  1.0,
  1.0,
  1.0,
  1.0,
  1.0
};

#define BW_FILTER_LEN 10

const double C = 10.0; // bottleneck_link_bw

struct bbr_flow {
  int index;               /* flow identifier */
  double max_bw;           /* current estimated bw */
  double sending_bw;       /* current receive bw */
  double receive_bw;       /* current receive bw */
  double bw_samples[BW_FILTER_LEN];
  int phase_offset;
};

struct bbr_flow f1;
struct bbr_flow f2;
struct bbr_flow f3;

int t = 0;
int bw_filter_index = 0;

#define max(a, b) (a > b) ? (a) : (b)
#define min(a, b) (a < b) ? (a) : (b)

void bbr_set_max_bw(struct bbr_flow *f)
{
  int i = 0;

  f->max_bw = 0;
  for (i = 0; i < BW_FILTER_LEN; i++) {
    f->max_bw = max(f->max_bw, f->bw_samples[i]);
  }
}

void bbr_update_max_bw(struct bbr_flow *f)
{
  f->bw_samples[bw_filter_index] = f->receive_bw;
  bbr_set_max_bw(f);
}

void bbr_update_sending_bw(struct bbr_flow *f)
{
  // Calculate new sending rate in the next phase:
  int phase = (t + f->phase_offset) % BW_CYCLE_LEN;
  const double pacing_gain = pacing_gain_cycle[phase];
  f->sending_bw = pacing_gain * f->max_bw;
  printf("flow %d phase: %d max_bw: %.3f sending_bw: %.3f\n",
         f->index, phase, f->max_bw, f->sending_bw);
}


void simulate_one_phase(void) {
  bbr_update_sending_bw(&f1);
  bbr_update_sending_bw(&f2);
  bbr_update_sending_bw(&f3);

  printf("t= %04d sending: f1: %.3f f2: %.3f f3: %.3f\n",
         t, f1.sending_bw, f2.sending_bw, f3.sending_bw);

  // On link A:
  // tmp is the rate of traffic sent to link B from flow 1.
  double tmp = C * f1.sending_bw / (f1.sending_bw + f2.sending_bw);  
  f2.receive_bw =  C * f2.sending_bw / (f1.sending_bw + f2.sending_bw);


  // On link B:
  f1.receive_bw = C * tmp / (tmp + f3.sending_bw);
  f3.receive_bw = C * f3.sending_bw / (tmp + f3.sending_bw);

  printf("t= %04d receive: f1: %.3f f2: %.3f f3: %.3f\n",
         t, f1.receive_bw, f2.receive_bw, f3.receive_bw);

  bbr_update_max_bw(&f1);
  bbr_update_max_bw(&f2);
  bbr_update_max_bw(&f3);

  printf("t= %04d  max_bw: f1: %.3f f2: %.3f f3: %.3f\n\n",
         t, f1.max_bw, f2.max_bw, f3.max_bw);

  t++;
  bw_filter_index = (bw_filter_index + 1) % BW_FILTER_LEN;
}

int main(int argc, char *argv[]) {
  int i = 0;

  f1.index = 1;
  f2.index = 2;
  f3.index = 3;

  f1.max_bw = 0.5 * C;
  f2.max_bw = 0.5 * C;
  f3.max_bw = 0.5 * C;

  f1.bw_samples[BW_FILTER_LEN - 1] = f1.max_bw;
  f2.bw_samples[BW_FILTER_LEN - 1] = f2.max_bw;
  f3.bw_samples[BW_FILTER_LEN - 1] = f3.max_bw;
  
  f1.phase_offset = 0;
  f2.phase_offset = 2;
  f3.phase_offset = 4;
  
  for (i = 0; i < 500; i++) {
    simulate_one_phase();
  }
  
  return 0;
}
