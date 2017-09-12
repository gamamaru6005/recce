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

# Readable Switch Construction without Lambdas or Dictionaries
# Source: https://code.activestate.com/recipes/410692-readable-switch-construction-without-lambdas-or-di/

class switch(object):
	def __init__(self, value):
		self.value = value
		self.fall = False

	def __iter__(self):
		"""Return the match method once, then stop"""
		yield self.match
		raise StopIteration

	def match(self, *args):
		"""Indicate whether or not to enter a case suite"""
		if self.fall or not args:
			return True
		elif self.value in args:  # changed for v1.5, see below
			self.fall = True
			return True
		else:
			return False
