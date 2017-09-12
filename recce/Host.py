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

class Host():
	def __init__(self, is_ip, host_detail):
		self.ipv4 = None
		self.hostname = None
		if is_ip:
			self.ipv4 = host_detail
		else:
			self.hostname = host_detail
		self.mac = '00:00:00:00:00:00'
		self.host_up = False
		self.ftp = None
		self.ssh = None
		self.telnet = None
		self.smtp = None
		self.dns = None
		self.dhcp = None
		self.tftp = None
		self.http = None
		self.pop = None
		self.imap = None
		self.snmp = None
		self.ldap = None
		self.rdp = None
		self.irc = None
		self.cifs = None
		self.nfs = None
		self.smb = None
		self.kerberos = None
		self.netbios = None
		self.syslog = None
		self.domains = []
		self.a = []
		self.mx = []
		self.ns = []
		self.txt = []

	def identify_ports(self, line):
		line = line.replace('/', ' ').split(' ')
		self.identify_ftp(line)

	def identify_ftp(self, line):
		if 'ftp' in line:
			self.ftp = line[0] + '/' + line[1]

	def identify_ssh(self, line):
		if 'ssh' in line:
			self.ssh = line[0] + '/' + line[1]

	def identify_telnet(self, line):
		if 'telnet' in line:
			self.telnet = line[0] + '/' + line[1]

	def identify_smtp(self, line):
		if 'smtp' in line:
			self.smtp = line[0] + '/' + line[1]

	def identify_dns(self, line):
		multi_port = []
		if 'dns' in line:
			if self.dns == 1:  # there is already an open DNS port registered
				multi_port.append(self.dns)  # append the old entry
				multi_port.append(line[0] + '/' + line[1])  # append the new entry
				self.dns = multi_port
			elif self.dns > 1:  # we have already initialised the array
				self.dns.append(line[0] + '/' + line[1])
			else:  # self.http has not been set
				self.dns = line[0] + '/' + line[1]

	def identify_dhcp(self, line):
		if 'dhcp' in line:
			self.dhcp = line[0] + '/' + line[1]

	def identify_tftp(self, line):
		if 'tftp' in line:
			self.tftp = line[0] + '/' + line[1]

	def identify_http(self, line):  # and obviously https
		multi_port = []
		if 'http' in line or 'https' in line:
			if self.http == 1:  # there is already an open HTTP port registered
				multi_port.append(self.http)  # append the old entry
				multi_port.append(line[0] + '/' + line[1])  # append the new entry
				self.http = multi_port
			elif self.http > 1:  # we have already initialised the array
				self.http.append(line[0] + '/' + line[1])
			else:  # self.http has not been set
				self.http = line[0] + '/' + line[1]

	def identify_pop(self, line):
		if 'pop' in line:
			self.pop = line[0] + '/' + line[1]

	def identify_imap(self, line):
		if 'imap' in line:
			self.imap = line[0] + '/' + line[1]

	def identify_snmp(self, line):
		if 'snmp' in line:
			self.snmp = line[0] + '/' + line[1]

	def identify_ldap(self, line):  # and ldaps
		if 'ldap' in line:
			self.ldap = line[0] + '/' + line[1]

	def identify_rdp(self, line):
		if 'rdp' in line:
			self.rdp = line[0] + '/' + line[1]

	def identify_irc(self, line):
		if 'irc' in line:
			self.irc = line[0] + '/' + line[1]

	def indentify_cifs(self, line):
		if 'cifs' in line:
			self.cifs = line[0] + '/' + line[1]

	def identify_nfs(self, line):
		if 'nfs' in line:
			self.nfs = line[0] + '/' + line[1]

	def identify_smb(self, line):
		if 'smb' in line:
			self.smb = line[0] + '/' + line[1]

	def identify_kerberos(self, line):
		if 'kerberos' in line:
			self.kerberos = line[0] + '/' + line[1]

	def identify_netbios(self, line):
		if 'telnet' in line:
			self.netbios = line[0] + '/' + line[1]

	def identify_live_host(self, line):
		if 'open' in line:
			self.host_up = True
