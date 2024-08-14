#!/bin/bash

./parking_lot_sim > out

# Graph flow's estimated bw ("ax_bw") over time.
cat out | egrep '^t=.*max_bw:' | awk '{print $2, $5, $7, $9}' > max_bw 
echo -e "
set yrange [0:10]\n\
set terminal pngcairo noenhanced size 1024,768\n\
set xlabel 'time (round trip number)'\n\
set ylabel 'estimated bandwidth (Mbit/sec)'\n\
set output 'max_bw.png'\n\
plot 'max_bw'  u 1:2 t 'flow 1', 'max_bw' u 1:3 t 'flow 2', 'max_bw'  u 1:4 t 'flow 3'\n" > max_bw.gnuplot
gnuplot < max_bw.gnuplot


# Graph receive rate ("receive") over time.
cat out | egrep '^t=.*receive:' | awk '{print $2, $5, $7, $9}' > receive
echo -e "
set yrange [0:10]\n\
set terminal pngcairo noenhanced size 1024,768\n\
set xlabel 'time (round trip number)'\n\
set ylabel 'received bandwidth (Mbit/sec)'\n\
set output 'receive.png'\n\
plot 'receive'  u 1:2 t 'flow 1', 'receive' u 1:3 t 'flow 2', 'receive'  u 1:4 t 'flow 3'\n" > receive.gnuplot
gnuplot < receive.gnuplot

