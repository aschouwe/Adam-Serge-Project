#!/usr/bin/env python3

import sys
import os
from datetime import datetime
#variable for any pcap file from the command line
file_name = sys.argv[1]

about = "Welcome to PyBash Auto-parsing Tool!"
print(about)
#user input variable
key = input("***Press ENTER to Contiue***")
print(key)

#variable for current time
now = datetime.now()
#formating for current time
current = now.strftime("%H:%M:%S")


#create a directory called "exports" 
cmd_dir = 'mkdir exports' + current
print("                                ")
print("********************************")
print('New "exports" Directory Created!')
print("********************************")
#call create directory command
os.system(cmd_dir)

#read pcap with tshark and save to file
cmd_file = 'tshark -r ' + str(file_name) + ' > /home/kali/finalproject/pcap.log'

os.system(cmd_file)

#cut timestamp out of pcap log file
cut_cmd = 'cut -d " " -f 2 /home/kali/finalproject/pcap.log > timestamp.log'
#call cut command
os.system(cut_cmd)
#cut timestamp into first part only, at the (.)
cut_cmd2 = 'cut -d "." -f 1 timestamp.log | sort > cutstamp.log'
#call cut command
os.system(cut_cmd2)

#parse all src ips sort and count them
cmd = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.src | sort | uniq -c | sort -n'
#parse all dst ips sort and count them
cmd2 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.dst | sort | uniq -c | sort -n'
#parse all src ports and count them
cmd3 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.srcport | sort | uniq -c | sort -n'
#parse all dst ports and count them
cmd4 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.dstport | sort | uniq -c | sort -n'
# parse all http traffic 
cmd5 = 'tshark -r ' + str(file_name) + ' -Y http | sort -n'
#export all http objects to current exports directory and redirected stdout to dev null
cmd6 = 'tshark -r ' + str(file_name) + ' --export-object http,/home/kali/finalproject/exports' + current + '> /dev/null'

#header formating
print("---------------------")
print("SOURCE IPs")
print("---------------------")
print("Count | Ips          ")
print("---------------------")
#call tshark shell command()
os.system(cmd)

#hearder formating
print("                     ")
print("---------------------")
print("DESTINATION IPs      ")
print("---------------------")
print("Count | Ips          ")
print("---------------------")
#call tshark shell command(2)
os.system(cmd2)

#header formating
print("                     ")
print("---------------------")
print("SOURCE PORTS         ")
print("---------------------")
print("Count | Port         ")
print("---------------------")
#call tshark shell command(3)
os.system(cmd3)

#header formating
print("                     ")
print("---------------------")
print("DESTINATION PORTS    ")
print("---------------------")
print("Count | port         ")
print("---------------------")
#call tshark shell command(4)
os.system(cmd4)

#header formating
print("                     ")
print("---------------------")
print("ALL HTTP TRAFFIC     ")
print("---------------------")
#call tshark shell command(5)
os.system(cmd5)

#header formating
print("                                                ")
print("************************************************")
print("HTTP OBJECTS SAVED TO RECENT EXPORTS DIRECTORY  ")
print("************************************************")
#call tshark shell command(5)
os.system(cmd6)

#header formating
print("                     ")
print("---------------------")
print("TIMELINE (DECODED)   ")
print("---------------------")

#function to convert unix timestamp 
def timeconvert(file):
    #emtpy timestamp list
    ts = []
    #empty trash list (for unwanted chars)
    trash = []
    #iterate through cutstamp.log file and remove unwanted chars
    for line in file:
        line = line.rstrip()
        #if the line is a number, then add to the timestamp list
        if line.isnumeric():
            ts.append(line)
        #if line is not a number, then add to the trash list
        else:
            trash.append(line)
    #iterate through the timestamp list
    for num in ts:
        #decode every unix timestamp into human readable format
        dt = datetime.fromtimestamp(int(num))
        #print decoded timestamp in stdout
        print(dt)
    #remove timestamp files from system
    cmd_rm = 'rm -r cutstamp.log timestamp.log pcap.log'
    os.system(cmd_rm)
            
        
        
        
#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/cutstamp.log')
    with open(file_name) as file_name:
        #call function
        timeconvert(file_name)

#dunder check
if __name__ == "__main__":
 main()

#portscan filter
cmd_arpscn = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" > ARPscanning.log' + current
os.system(cmd_arpscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > arpscan.count' + current
os.system(cnt_pcap)
#count number of line in portscan filter
print("                           ")
print("---------------------------")
print("ARP Scan PACKETS FOUND     ")
print("---------------------------")
cmd_arpscncnt = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" | wc -l'
os.system(cmd_arpscncnt)
cmd_arpcnt = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" | wc -l >> arpscan.count' + current
os.system(cmd_arpcnt)

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
    file_name = ('/home/kali/finalproject/arpscan.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r arpscan.count*'
os.system(cmd_rm)

#ssh traffic filter
cmd_sshtraff = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" > SSHtraffic.log' + current
os.system(cmd_sshtraff)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > ssh.count' + current
os.system(cnt_pcap)
#count number of line in ssh filter
print("                           ")
print("---------------------------")
print("SSH Traffic PACKETS FOUND  ")
print("---------------------------")
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

#syn flood filter
cmd_syn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" > SYNflood.log' + current
os.system(cmd_syn)
#count number of packets in the pcap
cmd_cnt = 'tshark -r ' + str(file_name) + ' | wc -l > syn.count' + current
os.system(cmd_cnt)
#count number of line in syn flood filter
print("                           ")
print("---------------------------")
print("SYN Scan PACKETS FOUND     ")
print("---------------------------")
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | wc -l'
os.system(cmd_syncnt)
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | wc -l >> syn.count' + current
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
    file_name = ('/home/kali/finalproject/syn.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r syn*'
os.system(cmd_rm)

#icmp filter
cmd_icmp = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" > ICMPsweep.log' + current
os.system(cmd_icmp)
#count number of packets in the pcap
cnt_icmp = 'tshark -r ' + str(file_name) + ' | wc -l > icmp.count' + current
os.system(cnt_icmp)

print("                           ")
print("---------------------------")
print("ICMP Ping Sweep PACKETS FOUND")
print("---------------------------")
cmd_icmpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l'
os.system(cmd_icmpcnt)
cmd_icmpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l >> icmp.count' + current
os.system(cmd_icmpcnt)

def percent(file):

    icmpnums = []
    for line in file:
        line = line.rstrip()
        if line.isnumeric():
            icmpnums.append(line)
  
    x = icmpnums[0]
    y = icmpnums[1]

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

cmd_rm = 'rm -r icmp.count*'
os.system(cmd_rm)

#udpscan filter
cmd_udpscn = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" > UDPscanning.log' + current
os.system(cmd_udpscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > udpscan.count' + current
os.system(cnt_pcap)
#count number of line in portscan filter
print("                           ")
print("---------------------------")
print("UDP Scan PACKETS FOUND     ")
print("---------------------------")
cmd_udpscncnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" | wc -l'
os.system(cmd_udpscncnt)
cmd_udpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" | wc -l >> udpscan.count' + current
os.system(cmd_udpcnt)

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
    file_name = ('/home/kali/finalproject/udpscan.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r udpscan.count*'
os.system(cmd_rm)

#portscan filter
cmd_portscn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1"> PORTscanning.log' + current
os.system(cmd_portscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > portscan.count' + current
os.system(cnt_pcap)
#count number of line in portscan filter
print("                           ")
print("---------------------------")
print("Port Scanning PACKETS FOUND")
print("---------------------------")
cmd_portscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1" | wc -l'
os.system(cmd_portscncnt)
cmd_portcnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1" | wc -l >> portscan.count' + current
os.system(cmd_portcnt)

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
    file_name = ('/home/kali/finalproject/portscan.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r portscan.count*'
os.system(cmd_rm)

#xmas scan filter
cmd_xmasscn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" > XMASscanning.log' + current
os.system(cmd_xmasscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > xmasscan.count' + current
os.system(cnt_pcap)
#count number of line in portscan filter
print("                           ")
print("---------------------------")
print("XMAS Scan PACKETS FOUND")
print("---------------------------")
cmd_xmasscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" | wc -l'
os.system(cmd_xmasscncnt)
cmd_xmascnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" | wc -l >> xmasscan.count' + current
os.system(cmd_xmascnt)

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
    file_name = ('/home/kali/finalproject/xmasscan.count' + current)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r xmasscan.count*'
os.system(cmd_rm)
