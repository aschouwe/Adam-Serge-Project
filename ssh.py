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

#portscan filter
cmd_sshtraff = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" > SSHtraffic.log' + current
os.system(cmd_sshtraff)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > ssh.count' + current
os.system(cnt_pcap)
#count number of line in ssh filter
print("                     ")
print("---------------------")
print("SSH Traffic PACKETS FOUND")
print("---------------------")
cmd_sshscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" | wc -l'
os.system(cmd_sshscncnt)
cmd_sshcnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" | wc -l >> ssh.count' + current
os.system(cmd_sshcnt)

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
    file_name = ('/home/kali/finalproject/ssh.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r ssh.count*'
os.system(cmd_rm)
