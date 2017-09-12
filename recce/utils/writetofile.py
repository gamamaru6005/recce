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

def write_to_markdown(filepath, message, level):
	print 'writing stuff'


def write_to_text(filepath, message):
	with open(filepath, 'a+') as file:
		file.write(message)


def write_to_html(filepath, message, level):
	print 'stuff'
	# just call the markdown function
	# then convert to HTML :D
