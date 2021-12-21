#!/usr/bin/env python3

import sys
import os
from datetime import datetime
#variable for any pcap file from the command line
file_name = sys.argv[1]

#variable for current time
now = datetime.now()
#formating for current time
current = now.strftime("%H:%M:%S")

#syn flood filter
cmd_syn = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" > ICMPsweep.log' + current
os.system(cmd_syn)
#count number of packets in the pcap
cmd_cnt = 'tshark -r ' + str(file_name) + ' | wc -l > icmp.count' + current
os.system(cmd_cnt)
#count number of line in syn flood filter
print("                     ")
print("---------------------")
print("ICMP PACKETS FOUND   ")
print("---------------------")
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l'
os.system(cmd_syncnt)
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l >> icmp.count' + current
os.system(cmd_syncnt)

def percent(file):

    nums = []
    for line in file:
        line = line.rstrip()
        if line.isnumeric():
            nums.append(line)
  
    x = nums[0]
    y = nums[1]

    math = (int(y) / int(x)) * 100 * 10
    rounder = round(math,2)
    percent = "%"
    print("---------------------------")
    print("Percentage of total packets")
    print("---------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/icmp.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r icmp*'
os.system(cmd_rm)
