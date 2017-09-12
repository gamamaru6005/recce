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

import argparse
import errno
import os

from recce.discovery import discovery_cnc
from recce.dns import dns_cnc
from recce.utils import addresshandler
from recce.utils.customprint import printf


def print_banner():
	print('something something tool for scanning shit')


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target',
						dest="target_hosts",
						required=True,
						help="Set a target range of addresses to target. Ex 10.11.1.1-255")

	parser.add_argument("-o", '--output-location',
						dest="output_directory",
						required=True,
						help="Set the output directory. Ex /root/Documents/labs/")

	parser.add_argument("-w",
						dest="wordlist",
						required=False,
						help="Set the wordlist to use for generated commands. Ex /usr/share/wordlist.txt")

	parser.add_argument('-p', "--pingsweep",
						dest="pingsweep",
						action="store_true",
						help="Write a new target.txt by performing a ping sweep and discovering live hosts.",
						default=False)

	parser.add_argument('-d', "--discovery",
						dest="discovery",
						action="store_true",
						help="Write a new target.txt by performing a discovery scan, helpful if ping sweep fails.",
						default=False)

	parser.add_argument('-D', "--dns",
						dest="dns",
						action="store_true",
						help="Find DNS servers from a list of targets.",
						default=False)

	parser.add_argument('-s', "--snmp",
						dest="snmp",
						action="store_true",
						help="Perform service scan over targets.",
						default=False)

	parser.add_argument("--quiet",
						dest="quiet",
						action="store_true",
						help="Suppress banner and headers to limit to comma dilimeted results only.",
						default=False)

	parser.add_argument('-R', "--resolve",
						dest="domain_ip",
						action="store_true",
						help="If using a domain instead of an IP, resolve address to an IP and then scan. If not set"
							 "not all scans will run.",
						default=False)

	args = vars(parser.parse_args())

	# Check if the output directory exists, else creates it
	try:
		os.makedirs(args['output_directory'])
	except OSError as e:
		if e.errno != errno.EEXIST:
			raise

	target_hosts = addresshandler.generate_ip_addresses(args['target_hosts'])

	if target_hosts is True:
		# it's actually a domain name not an ip address
		print('do stuff here with ip address')
		# check if flag to resolve to IP address is flagged

	if args['quiet'] is not True:
		print_banner()

	# Tools that can run on domain name
	#   - enum4linux
	#   - nmap
	if args['pingsweep'] is True:
		printf(5, 'Performing ping sweep', True, True, loglevel='info')
		discovery_cnc('ping', target_hosts, args['output_directory'], args['quiet'])

	if args['discovery'] is True:
		printf(5, 'Performing discovery scan... This may take longer than a ping sweep', True, True, loglevel='info')
		discovery_cnc('discovery', target_hosts, args['output_directory'], args['quiet'])

	if args['dns'] is True:
		printf(5, 'Performing DNS scan', True, True, loglevel='info')
		dns_cnc(target_hosts, args['quiet'])


if __name__ == '__main__':
	main()
