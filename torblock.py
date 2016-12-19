#!/usr/bin/python

# Block Tor Exit Nodes With Iptables
# Author: V. Alex Brennen <vab@mit.edu>
# License: This script is public domain
# Date: 2013-10-22

# Description:  This script attempts to block all known tor exit nodes (as
#		reported by the Tor Project's website) from communicating
#		with the server that it is run on using iptables firewalling
#		rules.

import sys
import re
import requests
import subprocess


# Validate numeric IP address
def numeric_ipaddr(ip):
	quads = ip.split('.')
	if( len(quads) != 4):
		return False;
	else:
		for quad in quads:
			byte = int(quad)
			if( (byte <= 0) and (byte >= 255) ):
				return False
			else:
				return True


# Validate public addressable IP address (not private, loopback, or broadcast)
# This function makes sure we do not cause system problems by banning the 
# loopback, broadcast, or any private IP networks that may be in use locally
# should the website return invalid exit addresses.
def public_ipaddr(ip):
	quads = ip.split('.')
	# Invalid
	if (int(quads[0]) == 0):
		return False
	# Loop back
	elif (int(quads[0]) == 127):
		return False
	# Broadcast
	elif((int(quads[0]) == 255) or (int(quads[1]) == 255) or (int(quads[2]) == 255) or (int(quads[3]) == 255)):
		return False
	# Private
	elif(int(quads[0]) == 10):
		return False
	elif((int(quads[0]) == 172) and ((int(quads[1]) > 15) and (int(quads[1]) < 32))):
		return False
	elif((int(quads[0]) == 192) and (int(quads[1]) == 168)):
		return False
	else:
		return True


# Execute iptables command to block a node after sanity checking
def blocknode(ip):
	if public_ipaddr(ip) and numeric_ipaddr(ip):
		ip = ip + "/32"
		try: subprocess.check_call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
 		except OSerror as e:
			if (e[0] == errno.EPERM):
			print >> sys.stderr, "Since this script modifies the firewall with iptables it must be run with root privileges."
      sys.exit(1)
		print "Dropping all packets from " + ip
	return True


# The main loop. It calls the blocknodes() function to attempt to open the
# file containing nodes to block, performs sanity checking, and then issues
# an iptables command to block a node. If it encounters a help request, it
# calls the usage() function to print the usage information and exit the
# program.

print "Blocking all tor exit nodes."

print "Retrieving list of nodes from Tor project website."
exits = "https://check.torproject.org/exit-addresses"

response = requests.get(exits, stream=True)
for line in response.iter_lines():
	if 'ExitAddress' in line:
		ip = line.split(' ', 3 )
		if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip[1]):
			blocknode(ip[1])

