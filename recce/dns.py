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

import re
import subprocess

from recce.utils.customprint import printf


def dns_cnc(target_hosts, quiet):
	__rdns__(target_hosts, quiet)
	__record_enumeration__(target_hosts, quiet)
	__zone_transfer__(target_hosts, quiet)
	__brute_subdomains__(target_hosts, quiet)


def __record_enumeration__(target_hosts, quiet):
	if len(target_hosts) == 1:
		if target_hosts[0].hostname is None:
			# attempt to resolve a hostname, if we can't we don't do record enumeration
			__rdns__(target_hosts, quiet)
			if target_hosts[0].hostname is None:
				return
			else:
				printf(13, 'Performing DNS Record Enumeration on {}'.format(target_hosts[0].hostname), True, True,
					   loglevel='info')
				__record_enumeration_run__(target_hosts[0])
		else:
			printf(13, 'Performing DNS Record Enumeration on {}'.format(target_hosts[0].hostname), True, True,
				   loglevel='info')
			__record_enumeration_run__(target_hosts[0])
	else:
		for target_host in target_hosts:
			if target_host.hostname is None:
				__rdns__(list(target_host), quiet)
				# attempt to resolve a hostname, if we can't we don't do record enumeration
				if target_host.hostname is None:
					return
				else:
					printf(13, 'Performing DNS Record Enumeration on {}'.format(target_hosts[0].hostname), True, True,
						   loglevel='info')
					__record_enumeration_run__(target_host)
			else:
				printf(13, 'Performing DNS Record Enumeration on {}'.format(target_hosts[0].hostname), True, True,
					   loglevel='info')
				__record_enumeration_run__(target_host)


def __record_enumeration_run__(target_host):
	record_types = ['a', 'mx', 'ns', 'txt']

	for record in record_types:
		SWEEP = 'dig {} {}'.format(target_host.hostname, record)
		results = subprocess.check_output(SWEEP, shell=True)
		results = results.split('\n')

		__parse_record_enumeration__(target_host, record, results)


def __parse_record_enumeration__(target_host, record_type, results):
	spacing_regex = re.compile('(\t|\s)*')
	if record_type.lower() == 'a':
		for line in results:
			if 'answer section' in line.lower():
				printf(7, 'A record found', True, True, loglevel='info')
			elif not line.startswith(';'):
				if 'IN\tA' in line:
					printf(11, '{}'.format(line), True, True, loglevel='info')
					line = re.split(spacing_regex, line)
					target_host.a.append(line[8])
	elif record_type.lower() == 'mx':
		for line in results:
			if 'answer section' in line.lower():
				printf(7, 'MX record found', True, True, loglevel='info')
			elif not line.startswith(';'):
				if 'IN\tMX' in line:
					printf(11, '{}'.format(line), True, True, loglevel='info')
					line = line.split('\t')
					line = re.split(spacing_regex, line)
					target_host.mx.append(line[8])
	elif record_type.lower() == 'ns':
		for line in results:
			if 'answer section' in line.lower():
				printf(7, 'NS record found', True, True, loglevel='info')
			elif not line.startswith(';'):
				if 'IN\tNS' in line:
					printf(11, '{}'.format(line), True, True, loglevel='info')
					line = line.split('\t')
					line = re.split(spacing_regex, line)
					target_host.ns.append(line[8])
	elif record_type.lower() == 'txt':
		for line in results:
			if 'answer section' in line.lower():
				printf(7, 'TXT record found', True, True, loglevel='info')
			elif not line.startswith(';'):
				if 'IN\tTXT' in line:
					printf(11, '{}'.format(line), True, True, loglevel='info')
					line = line.split('\t')
					line = re.split(spacing_regex, line)
					target_host.txt.append(line[8])


def __rdns__(target_hosts, quiet):
	if len(target_hosts) == 1:
		if target_hosts[0].ipv4 is None:
			printf(2, 'Unable to do reverse lookup on {}. IP address not set'.format(target_hosts[0].hostname),
				   True, True, loglevel='warning')
		else:
			if not quiet:
				if target_hosts[0].ipv4 is None:
					printf(2, 'Unable to do reverse lookup on {}. IP address not set'.format(target_hosts[0].hostname),
						   True, True, loglevel='warning')
					return False
				else:
					printf(13, 'Performing Reverse Lookup on {}'.format(target_hosts[0].ipv4), True, True,
						   loglevel='info')
			rdns = __rdns_run__(target_hosts[0])
			__parse_rdns__(target_hosts[0], rdns)
	else:
		if not quiet:
			printf(13, 'Performing Reverse Lookup on:', True, True, loglevel='info')
			for target_host in target_hosts:
				if target_host.ipv4 is None:
					printf(2, 'Unable to do reverse lookup on {}. IP address not set'.format(target_hosts[0].hostname),
						   True, True, loglevel='warning')
				else:
					printf(7, '{}'.format(target_host.ipv4), True, True, loglevel='info')

			for target_host in target_hosts:
				if not target_host.ipv4 is None:
					if not quiet:
						printf(13, 'Beginning lookup on {}'.format(target_host.ipv4), True, True, loglevel='info')
					rdns = __rdns_run__(target_host)
					__parse_rdns__(target_host, rdns)


def __rdns_run__(target_host):
	try:
		SWEEP = 'host {}'.format(target_host.ipv4)
		results = subprocess.check_output(SWEEP, shell=True)
		results = results.split('\n')
		return results
	except subprocess.CalledProcessError:
		return None


def __parse_rdns__(target_host, results):
	# todo unsure about shared hosting cases, plz find case in future for proper handling
	if not results:
		printf(2, 'Could not find domain pointer for {}'.format(target_host.ipv4), True, True, loglevel='info')
	else:
		for line in results:
			if 'name pointer' in line:
				line = line.rstrip('.')
				line = line.split(' ')
				line = line[len(line) - 1]
				printf(7, '{} points to {}'.format(target_host.ipv4, line), True, True, loglevel='info')
				target_host.hostname = line


def __zone_transfer__(target_hosts, quiet):
	if len(target_hosts) == 1:
		if target_hosts[0].hostname is None:
			# attempt to resolve a hostname, if we can't we don't do record enumeration
			__rdns__(target_hosts, quiet)
			if target_hosts[0].hostname is None:
				return
			else:
				if target_hosts[0].dns:
					printf(13, 'Attempting Zone Transfer on {}'.format(target_hosts[0].hostname), True, True,
						   loglevel='info')
					results = __run_zone_transfer__(target_hosts[0])
					__parse_dns_zone_transfer__(results)
				else:
					printf(2,
						   'Unable to perform Zone Transfer on host {}. No DNS port open'.format(
							   target_hosts[0].hostname), True, True,
						   loglevel='info')
					return
		else:
			if target_hosts[0].dns:
				printf(13, 'Attempting Zone Transfer on on {}'.format(target_hosts[0].hostname), True, True,
					   loglevel='info')
				results = __run_zone_transfer__(target_hosts[0])
				__parse_dns_zone_transfer__(results)
			else:
				printf(2,
					   'Unable to perform Zone Transfer on host {}. No DNS port open'.format(target_hosts[0].hostname),
					   True, True,
					   loglevel='info')
				return
	else:
		for target_host in target_hosts:
			if target_host.hostname is None:
				__rdns__(list(target_host), quiet)
				# attempt to resolve a hostname, if we can't we don't do record enumeration
				if target_host.hostname is None:
					return
				else:
					if target_host.dns:
						printf(13, 'Attempting Zone Transfer on {}'.format(target_host.hostname), True, True,
							   loglevel='info')
						results = __run_zone_transfer__(target_host)
						__parse_dns_zone_transfer__(results)
					else:
						printf(2,
							   'Unable to perform Zone Transfer on host {}. No DNS port open'.format(
								   target_host[0].hostname), True, True,
							   loglevel='info')
						return
			else:
				printf(13, 'Attempting Zone Transfer on on {}'.format(target_host[0].hostname), True, True,
					   loglevel='info')
				results = __run_zone_transfer__(target_host)
				__parse_dns_zone_transfer__(results)


def __run_zone_transfer__(target_host):
	# todo cover that case where dns is internal.
	# you will need to search the range for any open dns ports and then use those ip addresses
	# as the dns server
	SWEEP = 'nmap --script dns-zone-transfer {}'.format(target_host.hostname)
	results = subprocess.check_output(SWEEP, shell=True)
	results = results.split('\n')

	return results


def __parse_dns_zone_transfer__(results):
	for line in results:
		# todo this probably will need to be changed, find live service that has zone transfers lol
		if 'domain' in line:
			printf(7, 'Zone transfer possible.', True, True, loglevel='info')
		elif 'dns-zone-transfer' in line:
			pass
		else:
			line = line.rstrip('\n')
			line = line.strip('|  ')
			line = line.strip('|_ ')
			printf(11, line, True, True, loglevel='info')


def __brute_subdomains__(target_hosts, quiet):
	if len(target_hosts) == 1:
		if target_hosts[0].hostname is None:
			# attempt to resolve a hostname, if we can't we don't do record enumeration
			__rdns__(target_hosts, quiet)
			if target_hosts[0].hostname is None:
				return
			else:
				printf(13, 'Attempting Subdomain brute force on {}'.format(target_hosts[0].hostname), True, True,
					   loglevel='info')
				results = __run_brute_subdomains__(target_hosts[0])
				__parse_brute_subdomains__(results)
		else:
			printf(13, 'Attempting Subdomain brute force on {}'.format(target_hosts[0].hostname), True, True,
				   loglevel='info')
			results = __run_brute_subdomains__(target_hosts[0])
			__parse_brute_subdomains__(results)
	else:
		for target_host in target_hosts:
			if target_host.hostname is None:
				__rdns__(list(target_host), quiet)
				# attempt to resolve a hostname, if we can't we don't do record enumeration
				if target_host.hostname is None:
					return
				else:
					printf(13, 'Attempting Subdomain brute force on {}'.format(target_host.hostname), True, True,
						   loglevel='info')
					results = __run_brute_subdomains__(target_host)
					__parse_brute_subdomains__(results)
			else:
				printf(13, 'Attempting Subdomain brute force on {}'.format(target_host.hostname), True, True,
					   loglevel='info')
				results = __run_brute_subdomains__(target_host)
				__parse_brute_subdomains__(results)


def __run_brute_subdomains__(target_host):
	SWEEP = 'nmap --script dns-brute {}'.format(target_host.hostname)
	results = subprocess.check_output(SWEEP, shell=True)
	results = results.split('\n')

	return results


def __parse_brute_subdomains__(results):
	# check if domain or IP
	# if domain brute subdomains using supplied list
	# else RDNS and attempt to resolve a domain
	for line in results:
		if 'DNS Brute-force hostnames' in line:
			printf(7, 'DNS Brute-forse results:.', True, True, loglevel='info')

		if 'no results' in line.lower():
			printf(2, 'No subdomains found! There may be no RDNS record set for the host', True, True, info='info')
		elif '|     ' in line:
			line = line.rstrip('\n')
			line = line.strip('|  ')
			line = line.strip('|_ ')
			printf(11, line, True, True, loglevel='info')
