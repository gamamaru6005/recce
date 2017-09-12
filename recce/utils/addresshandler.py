# recce - a security tool for information gathering and service enumeration
# Copyright (C) 2017 errbufferoverfl
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import csv
import os
import re
import sys
from urlparse import urlparse

import ipaddress

from recce.Host import Host
from recce.utils.customprint import printf


def generate_ip_addresses(target_hosts):
	singleip_regex = re.compile('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
	rangeip_regex = re.compile('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}-\d{1,3}')
	cidrblock_regex = re.compile('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d{1,2}')

	hosts = []

	# Loads a .csv file or .txt file
	if os.path.isfile(target_hosts):
		# Checks if extension is .csv
		if str(target_hosts).lower().endswith('.csv'):
			with open(target_hosts, 'r') as file:
				reader = csv.reader(file)
				for row in reader:
					if singleip_regex.match(row):
						hosts.append(Host(True, row))
					else:
						printf(1, 'Malformed IP address {}'.format(row), True, True, loglevel='warning')
						sys.exit(41)

		# Checks for a txt file
		elif str(target_hosts).lower().endswith('.txt'):
			with open(target_hosts, 'r') as file:
				reader = file.readlines()
				for row in reader:
					if singleip_regex.match(row):
						hosts.append(Host(True, row))
					else:
						printf(1, 'Malformed IP address {}'.format(row), True, True, loglevel='warning')
						sys.exit(41)
		else:
			printf(1, 'Unknown file type, please ensure the file type is supported and has the '
					  'correct extension and try again', True, True, loglevel='critical')
			sys.exit(42)

	# Matches input against a range of ip addresses like 192.168.0.1-255
	elif rangeip_regex.match(target_hosts):
		ip = re.split(r'([.-])', target_hosts)

		start = int(ip[6])  # gets the start of the range
		end = int(ip[8])  # gets the end of the range
		ip = ''.join(ip[0:6])  # gets the base IP address

		# for the start range, until the end range generate all IP addresses in range
		for octet in range(start, end + 1):
			ipaddr = ''.join(ip + str(octet))
			hosts.append(Host(True, ipaddr))

	# Matches input again Classless Inter-Domain Routing (CIDR) IP addresses (192.168.0.0/22)
	elif cidrblock_regex.match(target_hosts):
		target_hosts = unicode(target_hosts)
		# By using strict we can provide any address in the range and don't need to worry about accidentally setting
		# host bits
		target_hosts = ipaddress.ip_network(target_hosts, strict=False)

		# For our CIDR block, generate the IP address and append to a list
		for host in target_hosts.hosts():
			ipaddr = str(host)
			hosts.append(Host(True, ipaddr))

	# Matches a single IP address
	elif singleip_regex.match(target_hosts):
		hosts.append(Host(True, target_hosts))
	else:
		parsed = urlparse(target_hosts)
		# parsed.scheme = http | https | ftp | etc.
		# parsed.netloc = google.com | yahoo.com | etc.
		if parsed.path:
			# Valid domain
			hosts.append(Host(False, target_hosts))
		else:
			printf(1, 'Malformed IP address or domain {}'.format(parsed), True, True, loglevel='warning')
			sys.exit(41)

	return hosts
