from __future__ import print_function
from __future__ import unicode_literals

import time
import sys
from sshbase import SSH
import re

class Nexus(SSH):
	"""
	Cisco Nexus Switch Handler, with simple functions, such as login, show config, exce commands.
	
	"""
		
	def cleanup(self):
		"""Gracefully exit the SSH session."""
		self.write_channel("exit" + self.RETURN)
		
	def session_preparation(self):
		"""Prepare the session after the connection has been established."""
		pre_time  = time.time()
		self._test_channel_read(pattern=r'[>#]')
		self.ansi_escape_codes = True
		self.set_base_prompt()
		self.disable_paging()
		# Clear the read buffer
		time.sleep(.3 * self.global_delay_factor)
		self.clear_buffer()
		
	def normalize_linefeeds(self, a_string):
		"""Convert '\r\n' or '\r\r\n' to '\n, and remove extra '\r's in the text."""
		newline = re.compile(r'(\r\r\n|\r\n)')
		return newline.sub(self.RESPONSE_RETURN, a_string).replace('\r', '')
		
		
	def disable_paging(self, command="terminal length 0", delay_factor=1):
		"""Disable paging for Cisco/Nexus CLI method."""
		delay_factor = self.select_delay_factor(delay_factor)
		time.sleep(delay_factor * .1)
		self.clear_buffer()
		command = self.normalize_cmd(command)
		self.write_channel(command)
		output = self.read_until_prompt()
		return output
	

