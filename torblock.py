#!/usr/bin/python

# Block Tor Exit Nodes With Iptables
# Author: V. Alex Brennen <vab@mit.edu>
# License: This script is public domain
# Date: 2013-10-22

# Description: This script attempts to block known tor exit nodes from
#              communicating with the server that it is run on using
#              iptables firewalling rules.

import sys


# This function will print out the usage information
def usage():
	"""Prints usage information and exits."""
	print "Usage: torblock.py (text file containing \\n delimited list)"
	print "Example: torblock.py torexits.txt"
	print "Options: -h      This Help Text"
	print "         --help  This Help Text"
	print
	sys.exit(0)


# Numeric IP address
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
def blocknodes(arg):
	return


# If the script isn't given a file containing a list of tor exit nodes, it
# should provide usage information and exit.
if len(sys.argv) < 2:
	usage()
elif len(sys.argv) > 3:
	usage()


# The main loop. It calls the blocknodes() function to attempt to open the
# file containing nodes to block, performs sanity checking, and then issues
# an iptables command to block a node. If it encounters a help request, it
# calls the usage() function to print the usage information and exit the
# program.
for arg in sys.argv[1:]:
	if(arg == "-h" or arg == "--help"): 
		usage()
	else: 
		blocknodes(arg)

