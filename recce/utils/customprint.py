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

import logging
import time

from colored import fg, attr

from switch import switch


def printf(level, message, console, log, **loglevel):
	'''

	:param level: how much of a problem is this?
	:param message: the message to print/log
	:param console: print to console
	:param log: log to file
	:param loglevel: level to log (uses default python levels - debug, info, warning, critical)
	:return:
	'''

	'''
	!!!         0 - REALLY BAD, LIKE CRITICAL BAD
	!!          1 - SORTA BAD, MORE LIKE A WARNING
	!           2 - Ehhhhh, nothing will catch fire
	?           3 - 
	#           4 - 
	-           13 - 
	*           5 - Starting a something
	+           6 - Writing a something
	\t>         7 - Displaying a something level 1
	\t\t>       8 - Displaying a something level 2
	\t\t\t>     9 - Displaying a something level 3

	\t          10 - Displaying a something level 1a
	\t\t        11 - Displaying a something level 1b
	\t\t\t      12 - Displaying a something level 1c
	'''

	if console:
		for case in switch(level):
			pmessage = 'default message'
			if case(0):
				pmessage = '[{}!!!{}] {}'.format(fg(0), attr(0), message)
				break
			if case(1):
				pmessage = '[{}!!{}] {}'.format(fg(0), attr(0), message)
				break
			if case(2):
				pmessage = '[{}!{}] {}'.format(fg(0), attr(0), message)
				break
			if case(3):
				pmessage = '[{}?{}] {}'.format(fg(0), attr(0), message)
				break
			if case(4):
				pmessage = '[{}#{}] {}'.format(fg(0), attr(0), message)
				break
			if case(5):
				pmessage = '[{}*{}] {}'.format(fg(0), attr(0), message)
				break
			if case(6):
				pmessage = '[{}+{}] {}'.format(fg(0), attr(0), message)
				break
			if case(7):
				pmessage = '\t[{}>{}] {}'.format(fg(0), attr(0), message)
				break
			if case(8):
				pmessage = '\t\t[{}>{}] {}'.format(fg(0), attr(0), message)
				break
			if case(9):
				pmessage = '\t\t\t[{}>{}] {}'.format(fg(0), attr(0), message)
				break
			if case(10):
				pmessage = '\t{}'.format(message)
				break
			if case(11):
				pmessage = '\t\t{}'.format(message)
				break
			if case(12):
				pmessage = '\t\t\t{}'.format(message)
			if case(13):
				pmessage = '[{}-{}] {}'.format(fg(0), attr(0), message)
				break
			if case():
				print 'default case'

		print pmessage

	if log:
		if 'loglevel' in loglevel:
			llevel = loglevel['loglevel']
			logtofile(llevel, message)


def logtofile(loglevel, message):
	'''

	:param loglevel:
	:param message:
	:return:
	'''
	logging.basicConfig(filename='logs/reccelogs-{}.log'.format(int(time.time())), level=logging.DEBUG)

	for case in switch(loglevel.lower()):
		if case('info'):
			logging.info(message)
			break
		if case('warning'):
			logging.warning(message)
			break
		if case('error'):
			logging.error(message)
			break
		if case('critical'):
			logging.critical(message)
			break
