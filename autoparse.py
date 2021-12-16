#!/usr/bin/env python3

import sys
import os

#variable for any pcap file 
file_name = sys.argv[1]

#parse all src ips sort and count them
cmd = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.src | sort | uniq -c | sort -n'
#parse all dst ips sort and count them
cmd2 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e ip.dst | sort | uniq -c | sort -n'
#parse src ports and count them
cmd3 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.srcport | sort | uniq -c | sort -n'
#parse dst ports and count them
cmd4 = 'tshark -r ' + str(file_name) + ' -Y tcp -T fields -e tcp.dstport | sort | uniq -c | sort -n'
# parse all http traffic 
cmd5 = 'tshark -r ' + str(file_name) + ' -Y http | sort -n'
#print a space to separate headers

print("---------------------")
print("SOURCE IPs           ")
print("---------------------")
print("Count | Ips          ")
print("---------------------")
#call tshark shell command()
os.system(cmd)

#print a space to separate headers
print("                     ")
print("---------------------")
print("DESTINATION IPs      ")
print("---------------------")
print("Count | Ips          ")
print("---------------------")
#call tshark shell command(2)
os.system(cmd2)

#print a space to separate headers
print("                     ")
print("---------------------")
print("SOURCE PORTS         ")
print("---------------------")
print("Count | Port         ")
print("---------------------")
#call tshark shell command(3)
os.system(cmd3)

#print a space to separate headers
print("                     ")
print("---------------------")
print("DESTINATION PORTS    ")
print("---------------------")
print("Count | port         ")
print("---------------------")
#call tshark shell command(4)
os.system(cmd4)

#print a space to separate headers
print("                     ")
print("---------------------")
print("ALL HTTP TRAFFIC     ")
print("---------------------")
#call tshark shell command(5)
os.system(cmd5)
