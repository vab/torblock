torblock.py
===========

Torblock is a python script that will attempt to block all known tor exit
nodes from communicating with the system that it is run on using iptables
firewalling rules.

The script retrieves a list of tor exit nodes from the tor project web 
site ( https://check.torproject.org/exit-addresses ) list. It extracts
the IP addresses from the list, runs some sanity checks against them
and then uses the python subprocess module to pass the IP address to 
iptables. Iptables is told to drop all packets from the IPs with the 
following command:

iptables -A INPUT -s AAA.BBB.CCC.DDD/32 -j DROP

The script was written to run on Redhat Enterprise Linux. If you run a 
different version of Linux you may need to make some changes to the 
iptables arguments in the script. You may also need to make some changes
to the arguments if you run custom chains or need to log packets from the 
exit nodes.

The script requires the sys, re, requests, and subprocess modules. Those
modules should be installed on your RHEL system if you install the base python
packages with the exception of requests. If you need to install the requests
module on your RHEL system, you should be able to do it with the following yum
command:

yum install python-requests 

This script does require root privileges since it calls the iptables command
and modifies the system firewall. I believe the script is secure due to the 
use of the subprocess module and the sanity checking of the IP addresses 
retrieved from the Tor project web site. However, as with any program that is
given root privileges, you should utilize extreme caution when running it.

