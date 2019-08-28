#!/usr/bin/python

import commands
import os
import sys

pppid = int(os.popen("ps -p %d -oppid=" % os.getppid()).read().strip())
filename = '/tmp/sysctl_restore_%d.sh' % pppid

restore_file = open(filename, 'w')
print >> restore_file, '#!/bin/bash'

for a in sys.argv[1:]:
  sysctl = a.split('=')

  # save current value
  cur_val = commands.getoutput('cat ' + sysctl[0])
  print >> restore_file, 'echo "%s" > %s' % (cur_val, sysctl[0])

  # set new value
  cmd = 'echo "%s" > %s' % (sysctl[1], sysctl[0])
  os.system(cmd)

os.system('chmod u+x %s' % filename)
