#!/usr/bin/python

# Block Tor Exit Nodes With Iptables
# Author: V. Alex Brennen <vab@mit.edu>
# License: This script is public domain
# Date: 2013-10-22

# Description: This script attempts to block known tor exit nodes from
#              communicating with the server that it is run on using
#              iptables firewalling rules.

import sys
import re


# This function will print out the usage information
def usage():
	"""Prints usage information and exits."""
	print "Usage: torblock.py (text file containing \\n delimited list)"
	print "Example: torblock.py torexits.txt"
	print "Options: -h      This Help Text"
	print "         --help  This Help Text"
	print
	sys.exit(0)


# Execute iptables command to block a node after sanity checking
def blocknodes():
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
		blocknodes()

