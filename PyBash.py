#!/usr/bin/env python3

import sys
import os
from datetime import datetime
#variable for any pcap file from the command line
file_name = sys.argv[1]

print("                                      ")
print("                                      ")

about = "WelCoMe To PyBaSh AuTo-PaRsInG To0l!"
print(about)
key = input("***PRESS ENTER KEY TO CONTINUE***")
print(key)

#variable for current time
now = datetime.now()
#formating for current time
current = now.strftime("%H:%M:%S")
print(("CURRENT TIME = ") + str(current))

#add custom name to all files
name = ""

key = input("please enter ANY word with NO spaces: ")

name += key

#print(name)

#create a directory called "exports" 
cmd_dir = 'mkdir exports' + current + name
#create a directory called images 
cmd_dir2 = 'mkdir images' + current + name
#create a directory search filters
cmd_dir3 = 'mkdir search_filters' + current + name

print("                                                 ")
print("*************************************************")
print('New Directories Created; With Current time and word')
print("*************************************************")

#call create directory command
os.system(cmd_dir)
os.system(cmd_dir2)
os.system(cmd_dir3)

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

print("---------------------------------")
print("EVENT TIMELINE   ")
print("---------------------------------")

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

#parse all src ips sort and count them
cmd = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.src | sort | uniq -c | sort -n'
#parse all dst ips sort and count them
cmd2 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.dst | sort | uniq -c | sort -n'
#parse all src ports and count them
cmd3 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.srcport | sort | uniq -c | sort -n'
#parse all dst ports and count them
cmd4 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.dstport | sort | uniq -c | sort -n'

cmd6 = 'tshark -r ' + str(file_name) + ' --export-object http,/home/kali/finalproject/exports' + current + name + '> /dev/null'
#export all smb objects
cmd7 = 'tshark -r ' + str(file_name) + ' --export-object smb,/home/kali/finalproject/exports' + current + name + '> /dev/null'
#export imf objects
cmd8 = 'tshark -r ' + str(file_name) + ' --export-object imf,/home/kali/finalproject/exports' + current + name + '> /dev/null'


#header formating
print("---------------------------------")
print("SOURCE IP addresses by total")
print("---------------------------------")
print("total | addresses        ")
print("---------------------------------")
#call tshark shell command()
os.system(cmd)

#hearder formating
print("---------------------------------")
print("DESTINATION IP addresses by total")
print("---------------------------------")
print("total | addresses          ")
print("---------------------------------")
#call tshark shell command(2)
os.system(cmd2)

#header formating
print("---------------------------------")
print("SOURCE PORT numbers by total")
print("---------------------------------")
print("total | port numbers         ")
print("---------------------------------")
#call tshark shell command(3)
os.system(cmd3)

#header formating
print("---------------------------------")
print("DESTINATION PORT numbers by total")
print("---------------------------------")
print("total | port numbers       ")
print("---------------------------------")
#call tshark shell command(4)
os.system(cmd4)

#call tshark shell command(s)
os.system(cmd6)
os.system(cmd7)
os.system(cmd8)
#header formating


#all http filter
cmd_http = 'tshark -r ' + str(file_name) + ' -Y "http" | sort -n > HTTPtraffic.log' + current + name
os.system(cmd_http)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > http.count' + current + name
os.system(cnt_pcap)
#count number of line in portscan filter
print("---------------------------------")
print("HTTP Traffic PACKETS FOUND ")
print("---------------------------------")
cmd_http_cnt = 'tshark -r ' + str(file_name) + ' -Y "http" | wc -l'
os.system(cmd_http_cnt)
cmd_httpcnt = 'tshark -r ' + str(file_name) + ' -Y http | wc -l >> http.count' + current + name
os.system(cmd_httpcnt)

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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the http.count file as file_name
    file_name = ('/home/kali/finalproject/http.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r http.count*'
os.system(cmd_rm)

#arpscan filter
cmd_arpscn = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" > ARPscanning.log' + current + name
os.system(cmd_arpscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > arpscan.count' + current + name
os.system(cnt_pcap)
#count number of line in portscan filter
print("---------------------------------")
print("ARP Scan PACKETS FOUND     ")
print("---------------------------------")
cmd_arpscncnt = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" | wc -l'
os.system(cmd_arpscncnt)
cmd_arpcnt = 'tshark -r ' + str(file_name) + ' -Y "arp.dst.hw_mac==00:00:00:00:00:00" | wc -l >> arpscan.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/arpscan.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r arpscan.count*'
os.system(cmd_rm)

#ssh traffic filter
cmd_sshtraff = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" > SSHtraffic.log' + current + name
os.system(cmd_sshtraff)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > ssh.count' + current + name
os.system(cnt_pcap)
#count number of line in ssh filter
print("---------------------------------")
print("SSH Traffic PACKETS FOUND  ")
print("---------------------------------")
cmd_sshscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" | wc -l'
os.system(cmd_sshscncnt)
cmd_sshcnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.dstport==22 and frame contains "SSH"" | wc -l >> ssh.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/ssh.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r ssh.count*'
os.system(cmd_rm)

#syn flood filter
cmd_syn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" > SYNflood.log' + current + name
os.system(cmd_syn)
#count number of packets in the pcap
cmd_cnt = 'tshark -r ' + str(file_name) + ' | wc -l > syn.count' + current + name
os.system(cmd_cnt)
#count number of line in syn flood filter
print("---------------------------------")
print("SYN Scan PACKETS FOUND     ")
print("---------------------------------")
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | wc -l'
os.system(cmd_syncnt)
cmd_syncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" | wc -l >> syn.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/syn.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r syn*'
os.system(cmd_rm)

#icmp filter
cmd_icmp = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" > ICMPsweep.log' + current + name
os.system(cmd_icmp)
#count number of packets in the pcap
cnt_icmp = 'tshark -r ' + str(file_name) + ' | wc -l > icmp.count' + current + name
os.system(cnt_icmp)

print("---------------------------------")
print("ICMP Ping Sweep PACKETS FOUND")
print("---------------------------------")
cmd_icmpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l'
os.system(cmd_icmpcnt)
cmd_icmpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==8 or icmp.type==0" | wc -l >> icmp.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/icmp.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r icmp.count*'
os.system(cmd_rm)

#udpscan filter
cmd_udpscn = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" > UDPscanning.log' + current + name
os.system(cmd_udpscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > udpscan.count' + current + name
os.system(cnt_pcap)
#count number of line in portscan filter
print("---------------------------------")
print("UDP Scan PACKETS FOUND     ")
print("---------------------------------")
cmd_udpscncnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" | wc -l'
os.system(cmd_udpscncnt)
cmd_udpcnt = 'tshark -r ' + str(file_name) + ' -Y "icmp.type==3 and icmp.code==3" | wc -l >> udpscan.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/udpscan.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r udpscan.count*'
os.system(cmd_rm)

#portscan filter
cmd_portscn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1"> PORTscanning.log' + current + name
os.system(cmd_portscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > portscan.count' + current + name
os.system(cnt_pcap)
#count number of line in portscan filter
print("---------------------------------")
print("Port Scan PACKETS FOUND    ")
print("---------------------------------")
cmd_portscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1" | wc -l'
os.system(cmd_portscncnt)
cmd_portcnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags.syn == 1 or tcp.flags.reset == 1" | wc -l >> portscan.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/portscan.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r portscan.count*'
os.system(cmd_rm)

#xmas scan filter
cmd_xmasscn = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" > XMASscanning.log' + current + name
os.system(cmd_xmasscn)
#count number of packets in the pcap
cnt_pcap = 'tshark -r ' + str(file_name) + ' | wc -l > xmasscan.count' + current + name
os.system(cnt_pcap)
#count number of line in portscan filter
print("---------------------------------")
print("XMAS Scan PACKETS FOUND    ")
print("---------------------------------")
cmd_xmasscncnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" | wc -l'
os.system(cmd_xmasscncnt)
cmd_xmascnt = 'tshark -r ' + str(file_name) + ' -Y "tcp.flags==0X029" | wc -l >> xmasscan.count' + current + name
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
    print("---------------------------------")
    print("Percentage of total packets")
    print("---------------------------------")

    print(str(rounder) + str(percent)) 
    print("---------------------------------")
   

#main function to open a file
def main():
    #open the cutstamp.log file as file_name
    file_name = ('/home/kali/finalproject/xmasscan.count' + current + name)
    with open(file_name) as file_name:
        #call function
        percent(file_name)

#dunder check
if __name__ == "__main__":
 main()

cmd_rm = 'rm -r xmasscan.count*'
os.system(cmd_rm)

#move search filter results to filters directory
cmd_mv_filters = 'mv HTTP* ARP* ICMP* PORT* SSH* SYN* UDP* XMAS* -t ~/finalproject/search_filters' + current + name
os.system(cmd_mv_filters)
#remove all empty files from search filter directory 
rm_empty = 'find . -type f -empty -print -delete > /dev/null'
os.system(rm_empty)


print("****************************************************************")
print("ALL/ANY SEARCH FILTERS SENT TO CURRENT SEARCH FILTERS DIRECTORY")
print("****************************************************************")
print("****************************************************************")
print("ALL/ANY IMAGES SENT TO CURRENT IMAGES DIRECTORY")
print("****************************************************************")
print("****************************************************************")
print("ALL/ANY HTTP OBJECTS EXPORTED TO CURRENT EXPORTS DIRECTORY")
print("****************************************************************")
print("****************************************************************")
print("ALL/ANY SMB OBJECTS EXPORTED TO CURRENT EXPORTS DIRECTORY")
print("****************************************************************")
print("****************************************************************")
print("ALL/ANY IMF OBJECTS EXPORTED TO CURRENT EXPORTS DIRECTORY")
print("****************************************************************")
print("****************************************************************")

#change to exports directory
path = '/home/kali/finalproject/exports' + current + name
#move images to images directory, if no images exist errors will be redirected to dev/null
cmd_mv_images = 'mv *.gif *.jpg *.png -t /home/kali/finalproject/images' + current + name + '> /dev/null 2>&1'
#call os commands
os.chdir(path)
os.system(cmd_mv_images)

#change to final project directory
path2 = '/home/kali/finalproject/'
#call os command
os.chdir(path2)

#remove all empty directories from finalproject directory 
rm_empty2 = 'find . -type d -empty -print -delete > /dev/null'
#call os command
os.system(rm_empty2)
