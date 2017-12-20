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
		self.disable_paging(command="terminal length 0")
		# Clear the read buffer
		time.sleep(.3 * self.global_delay_factor)
		self.clear_buffer()
		
	def normalize_linefeeds(self, a_string):
		"""Convert '\r\n' or '\r\r\n' to '\n, and remove extra '\r's in the text."""
		newline = re.compile(r'(\r\r\n|\r\n)')
		return newline.sub(self.RESPONSE_RETURN, a_string).replace('\r', '')
		
	
	def save_config(self, delay_factor=1):
		"""Save current running congfig to startup file, use switch's default command."""
		delay_factor = self.select_delay_factor(delay_factor)
		time.sleep(delay_factor * .1)
		self.clear_buffer()
		command = self.normalize_cmd('copy running-config startup-config')
		self.write_channel(command)
		try:
			self.read_until_prompt(timeout=5)
		except:
			return False
		return True
		
	
		


class Huawei(SSH):
	"""
	Cisco Nexus Switch Handler, with simple functions, such as login, show config, exce commands.
	
	"""
	
	def cleanup(self):
		"""Gracefully exit the SSH session."""
		self.write_channel("quit" + self.RETURN)
		
	def session_preparation(self):
		"""Prepare the session after the connection has been established."""
		self._test_channel_read()
		self.set_base_prompt()
		self.disable_paging(command="screen-length 0 temporary")
		# Clear the read buffer
		time.sleep(.3 * self.global_delay_factor)
		self.clear_buffer()

	def set_base_prompt(self, pri_prompt_terminator='>', alt_prompt_terminator=']',
						delay_factor=1):
		"""
		Sets self.base_prompt

		Used as delimiter for stripping of trailing prompt in output.

		Should be set to something that is general and applies in multiple contexts. For Comware
		this will be the router prompt with < > or [ ] stripped off.

		This will be set on logging in, but not when entering system-view
		"""
		
		delay_factor = self.select_delay_factor(delay_factor)
		self.clear_buffer()
		self.write_channel(self.RETURN)
		time.sleep(.5 * delay_factor)

		prompt = self.read_channel()
		prompt = self.normalize_linefeeds(prompt)

		# If multiple lines in the output take the last line
		prompt = prompt.split(self.RESPONSE_RETURN)[-1]
		prompt = prompt.strip()

		# Check that ends with a valid terminator character
		if not prompt[-1] in (pri_prompt_terminator, alt_prompt_terminator):
			raise ValueError("Device prompt not found: {0}".format(prompt))

		# Strip off leading and trailing terminator
		prompt = prompt[1:-1]
		prompt = prompt.strip()
		self.base_prompt = prompt

		return self.base_prompt		
				
	def save_config(self, delay_factor=1):
		"""Save current running congfig to startup file, use switch's default command."""
		delay_factor = self.select_delay_factor(delay_factor)
		time.sleep(delay_factor * .1)
		self.clear_buffer()
		self.write_channel('save\n')
		self.read_until_prompt(pattern='\[Y/N\]', timeout=2)
		self.write_channel('y\n')
		output = self.read_until_prompt(timeout=5)
		if 'successfully' in output:
			return True
		else:
			return False