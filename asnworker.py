#!/usr/bin/python3
#
#    __ _ ___ _ __  ___  ___ __ _ _ __
#   / _` / __| '_ \/ __|/ __/ _` | '_ \
#  | (_| \__ \ | | \__ \ (_| (_| | | | |
#   \__,_|___/_| |_|___/\___\__,_|_| |_|
#    v1.0         Scan all the things..
#
#	WORKER MODULE / SCANTYPE DEFINITIONS
#
import sys
import os
import ipaddress

# check commandline
if len(sys.argv) == 3:
	scantype = sys.argv[1]
	ipfile = sys.argv[2]
else:
	print("NOTE: This script should be called by asnscan.sh (not manually)")
	print("usage: ./asnworker.py <SCANTYPE> </PATH/TO/IPLIST.TXT>")
	print("")
	exit()

########################################################################
# Add scantypes below this separator
########################################################################


# Non-CIDR Aware SCANTYPE Example (curl)
#
# - curl to POST form response & dump response w/cookie(s)
# - grep for a SESSIONID cookie to be set
# - positive result = print ip address
# - negative result = no ouput
#
if scantype == 'curl':
	with open(ipfile, "r") as list:
		for line in list:
			net4 = ipaddress.ip_network(line.strip())
			print("Scanning %s"%(line.strip()))
			for x in net4.hosts():
				command = "curl --max-time 5 -s -c - -d 'username=user&password=password' -X POST http://%s/userlogin | grep SESSION"%(x)
				test = (os.popen(command).read())
				if test != "":
					print("%s"%(x))
	os.remove(ipfile)
	exit()

# CIDR Aware SCANTYPE Example (nmap)
#
# - we don't loop for each individual address (nmap is CIDR aware)
# - simple command execution and output to stdout (which gets redirected to results file)
#
if scantype == 'nmap':
        with open(ipfile, "r") as list:
                for line in list:
                        print("Scanning %s"%(line.strip()))
                        command = "nmap -sS -sV -O %s"%(x)
                        os.popen(command).read()
        os.remove(ipfile)
        exit()


########################################################################
# Add scantypes above this separator
########################################################################
#
# ERROR if SCANTYPE was not matched
print("ERROR: %s has not been configured as a scan type"%(scantype))
exit()
