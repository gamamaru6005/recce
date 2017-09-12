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

import os
import re
import subprocess
import time

from recce.utils.customprint import printf

output_file = None
quiet = None
output_file = None


def discovery_cnc(scan_type, target_hosts, output_directory, quiet):
	quiet = quiet

	global output_file
	output_file = output_directory + '-{}'.format(time.time())

	if not os.path.exists(output_file):
		os.makedirs(output_file)
		global output_file
		output_file += '/targets.txt'

	if scan_type == 'ping':  # perform a ping scan
		__ping_scan__(target_hosts)

	elif scan_type == 'discovery':  # perform a discovery scan
		__discovery_scan__(target_hosts)


def __ping_scan__(target_hosts):
	if len(target_hosts) == 1:
		target_host = target_hosts[0].ipv4

		if not quiet:
			printf(13, 'Performing ping sweep over {}'.format(target_host), True, True, loglevel='info')

		results = __run_ping_scan__(target_host)
		__parse_ping_scan__(results)
	else:  # if there is more than one host to scan
		if not quiet:
			printf(13, 'Performing ping sweep over:', True, True, loglevel='info')
			for host in target_hosts:
				printf(7, '{}'.format(host.ipv4), True, True, loglevel='info')

		for target_host in target_hosts:
			if not quiet:
				printf(13, 'Beginning scan on {}'.format(target_host.ipv4), True, True, loglevel='info')

			results = __run_ping_scan__(target_host)
			__parse_ping_scan__(results)


def __run_ping_scan__(ip_address):
	# nmap ping scan with no dns resolution
	SWEEP = 'nmap -n -sP {}'.format(ip_address)
	results = subprocess.check_output(SWEEP, shell=True)
	results = results.split('\n')

	return results


def __parse_ping_scan__(results):
	try:
		for line in results:
			line = line.strip()
			line = line.rstrip()

			if 'nmap scan report for' in line:
				ip_address = line.split(' ')[4]
				if not quiet:
					printf(3, 'Discovered host: {}'.format(ip_address), True, True, loglevel='info')

	except ValueError:
		if not quiet:
			printf(0, 'No nmap output provided!', True, True, loglevel='info')


def __discovery_scan__(target_hosts):
	if len(target_hosts) == 1:
		if not quiet:
			printf(13, 'Performing discovery scan on {}'.format(target_hosts[0].ipv4), True, True, loglevel='info')

		results = __run_discovery_scan__(target_hosts[0])
		__parse_discovery_scan__(results, target_hosts[0])
	else:
		if not quiet:
			printf(13, 'Performing discovery scan over:', True, True, loglevel='info')
			for host in target_hosts:
				printf(7, '{}'.format(host.ipv4), True, True, loglevel='info')

		for target_host in target_hosts:
			if not quiet:
				printf(13, 'Beginning scan of {}'.format(target_host.ipv4), True, True, loglevel='info')

			results = __run_discovery_scan__(target_host)
			__parse_discovery_scan__(results, target_host)


def __run_discovery_scan__(ip_address):
	# nmap discovery scan
	SWEEP = 'nmap -n -Pn {}'.format(ip_address.ipv4)
	results = subprocess.check_output(SWEEP, shell=True)
	results = results.split('\n')
	return results


def __parse_discovery_scan__(results, target_host):
	port_regex = re.compile('(\d*)/(tcp|udp)(\w|\s|-)*')
	host_up_count = 0

	header = True

	for line in results:
		line = line.strip()
		line = line.rstrip()

		if 'nmap scan report for' in line.lower():
			# keep the ip address so we can log it
			ip_address = line.split(' ')[4]
			if not quiet:
				printf(7, 'Discovered host: {}'.format(ip_address), True, True, loglevel='info')
		elif 'not shown' in line.lower():
			# show how many filtered ports
			filtered_ports = line.split(' ')[2]
			if not quiet:
				printf(2, '{} filtered ports.'.format(filtered_ports), True, True, loglevel='info')
		elif 'all 1000 scanned ports on' in line.lower():
			if not quiet:
				printf(13, 'All scanned ports are filtered.', True, True, loglevel='info')
		elif re.match(port_regex, line):
			if header:
				if not quiet:
					printf(10, 'PORT\t  STATE\tSERVICE', True, True, loglevel='info')
				header = False
			else:
				target_host.identify_live_host(line)
				target_host.identify_ports(line)
				if not quiet:
					printf(10, '{}'.format(line), True, True, loglevel='info')

	if target_host.host_up:
		host_up_count = + 1

		with open(output_file, 'a+') as file:
			file.write('{}\n'.format(target_host.ipv4))

	if not quiet:
		if host_up_count > 0:
			printf(2, 'Found {} live hosts'.format(str(host_up_count)), True, True, loglevel='info')

	printf(6, 'Created target list {}'.format(output_file), True, True, loglevel='info')
