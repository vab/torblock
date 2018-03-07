#!/usr/bin/python3

# Block Tor Exit Nodes With Iptables
# Author: V. Alex Brennen <vab@protonmail.com>
# License: This script is public domain
# Date: 2013-10-22
# Last Updated: 2018-02-07

# Description:  This script attempts to block all known tor exit nodes (as
#			reported by the Tor Project's website) from communicating
#			with the server that it is run on using iptables firewalling
#			rules.

import sys
import errno
import argparse
import re
import requests
import subprocess


# Arguments
def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-a", "--apache", metavar="apachefile", type=argparse.FileType("a"), help="Write notes to Apache 2.4+ format file.")
	parser.add_argument("-a22", "--apache22", metavar="apache22file", type=argparse.FileType("a"), help="Write notes to Apache 2.2 format file.")
	parser.add_argument("-d", "--dryrun", action="store_true", help="Display nodes to block. But, take no action." )
	parser.add_argument("-n", "--nginx", metavar="nginxfile", type=argparse.FileType("a"), help="Write nodes to nginx deny format file.")
	parser.add_argument("-w", "--hostsdeny", metavar="Filename", type=argparse.FileType("a"), help="Write nodes to hosts.deny format file.")
	return parser.parse_args()


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


def blockapache(ip, out_file):
	out_file.write("\tRequire not ip " + ip + "/32\n")
	return


def blockapache22(ip, out_file):
	out_file.write("\tdeny from " + ip + "/32\n")
	return


def blocknginx(ip, out_file):
	out_file.write("deny {ip};\n".format(ip=ip))
	return


def hostsdeny(ip, out_file):
	out_file.write("ALL : " + ip + "\n")
	return


# Execute iptables command to block a node after sanity checking
def blocknode(ip):
	if public_ipaddr(ip) and numeric_ipaddr(ip):
		if args.dryrun:
			print("Dropping all packets from " + ip + "/32")
		elif args.apache:
			# Write to file in apache format
			blockapache(ip, args.apache)
			print("Adding " + ip + " to " + args.apache.name + " in apache format")
		elif args.apache22:
			# Write to file in deprecated apache v2.2 format
			blockapache22(ip, args.apache22)
			print("Adding " + ip + " to " + args.apache22.name + " in apache22 format")
		elif args.nginx:
			# Write to file in nginx information
			blocknginx(ip, args.nginx)
			print("Adding " + ip + " to " + args.nginx.name + " in nginx format")
		elif args.hostsdeny:
			# Write to file in hosts.deny format
			hostsdeny(ip, args.hostsdeny)
			print("Adding " + ip + " to " + args.hostsdeny.name + " in hosts.deny format")
		else:
			print("Dropping all packets from " + ip + "/32")
			ip = ip + "/32"
			try: subprocess.check_call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
			except OSError as e:
				if (e[0] == errno.EPERM):
					print("Since this script modifies the firewall with iptables it must be run with root privileges.", file=sys.stderr)
					sys.exit(1)
	return True


# The main loop. It calls the blocknodes() function to attempt to open the
# file containing nodes to block, performs sanity checking, and then issues
# an iptables command to block a node. If it encounters a help request, it
# calls the usage() function to print the usage information and exit the
# program.
args = parse_args()

print("Blocking all tor exit nodes.")

print("Retrieving list of nodes from Tor project website.")
exits = "https://check.torproject.org/exit-addresses"

response = requests.get(exits, stream=True)
for line in response.iter_lines():
	line = line.decode("UTF-8").strip()
	if 'ExitAddress' in line:
		ip = line.split(' ', 3 )
		if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip[1]):
			blocknode(ip[1])
