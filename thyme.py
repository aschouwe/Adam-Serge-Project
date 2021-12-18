#!/usr/bin/env python3

import time
import os

time = time.strftime("%Y%m%d-%H%M%S")
cmd = 'touch newfile.txt' + (time)

os.system(cmd)
