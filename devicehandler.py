from __future__ import print_function
from __future__ import unicode_literals

import time
import sys
import re
from sshbase import SSH

class Device(SSH):
	"""
	Generatinal Device Class Handler.
	"""
	
	def current_config(self, command="", section=None, delay_factor=1, timeout=None):
		"""
		Get current config of Device.
		:param section: The spcific part config, such as aaa,bgp, ospf. etc.
		:type  section: str
		
		"""
		if section is not None:
			command = command + ' ' + section
			
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)	
		
		
	def interface_config(self, command="", interface=None, if_type=None, delay_factor=1, timeout=None):
		"""
		Get current interface config of Device.
		
		:param interface: The spcific interface config, such as Eth1/1. Only one interface supported once.
		:type  interface: str
		
		:param if_type: The spcific type of interface, such as 40GE.
		:type  if_type: str	
		"""
		if interface is not None:
			command = command + ' ' + interface

		if if_type is not None:
			command = command + ' ' + if_type
			
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)	
		
		
		
	def macaddress_table(self, command="", vlan=None, interface=None, delay_factor=1, timeout=None):
		"""
		Get MacAddress Tables of Device
		
		:param vlan: The spcific vlan mac, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's mac, Only one interface supported once.
		:type  interface: str 	
		"""
		if vlan is not None:
			command = command + ' ' + str(vlan)
			
		if interface is not None:
			command = command + ' interface ' + interface
			
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)
		
		
	def arp_table(self, command="", vlan=None, interface=None, ipaddr=None, delay_factor=1, timeout=None):
		"""
		Get ARP Tables of Device
		
		:param vlan: The spcific vlan arp, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's arp, Only one interface supported once.
		:type  interface: str
		
		:param ipaddr: The spcific ip's arp, Only one ip supported once.
		:type  ipaddr: str
		
		"""
		_cmd = ''
		if vlan is not None:
			_cmd = ' vlan ' + str(vlan)
			
		if interface is not None:
			_cmd = ' interface ' + interface
			
		if ipaddr is not None:
			_cmd = ' ' + ipaddr
			
		command = command + _cmd
		
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)
		
		
	def interface_brief(self, command="", if_type=None, delay_factor=1, timeout=None):
		"""
		Get interface brief info of Device
		
		:param if_type: The spcific type of interface, such as 40GE.
		:type  if_type: str	
		"""	
		if if_type is not None:
			command = command + ' ' + str(vlan)
		
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)
	
	
	def save_config(self):
		"""Save congfig to disk. Implement by sub class"""
		raise NotImplementedError
	
	
		
class Nexus(Device):
	"""
	Cisco Nexus Switch SSH Handler, with simple functions, such as login, show config, exce commands.
	
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
		
		
	def current_config(self, command="show running", section=None, delay_factor=1, timeout=None):
		"""
		Get current config of Device.
		:param section: The spcific part config, such as aaa,bgp, ospf. etc.
		:type  section: str
		
		"""
		return super(Nexus, self).current_config(command=command, section=section, delay_factor=delay_factor,\
												  timeout=timeout)	
		
		
	def interface_config(self, command="show run interface", interface=None, if_type=None, delay_factor=1, timeout=None):
		"""
		Get current interface config of Device.
		
		:param interface: The spcific interface config, such as Eth1/1. Only one interface supported once.
		:type  interface: str
		
		"""
		return super(Nexus, self).interface_config(command=command, interface=interface, if_type=if_type, \
													delay_factor=delay_factor, timeout=timeout)
		

	def macaddress_table(self, command="show mac address-table", vlan=None, interface=None, delay_factor=1, timeout=None):
		"""
		Get MacAddress Tables of Device
		
		:param vlan: The spcific vlan mac, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's mac, Only one interface supported once.
		:type  interface: str 
		"""
		return super(Nexus, self).macaddress_table(command=command, vlan=vlan, interface=interface, \
													delay_factor=delay_factor, timeout=timeout)
		

	def arp_table(self, command="", vlan=None, interface=None, ipaddr=None, delay_factor=1, timeout=None):
		"""
		Get ARP Tables of Device
		
		:param vlan: The spcific vlan arp, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's arp, Only one interface supported once.
		:type  interface: str
		
		:param ipaddr: The spcific ip's arp, Only one ip supported once.
		:type  ipaddr: str
		
		"""
		_cmd = ''
		if vlan is not None:
			_cmd = ' ' + str(vlan)
			
		if interface is not None:
			_cmd = ' ' + interface
			
		if ipaddr is not None:
			_cmd = ' ' + ipaddr
			
		command += _cmd
			
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)
		
		
		
	def interface_brief(self, command="show interface brief", if_type=None, delay_factor=1, timeout=None):
		"""
		Get interface brief info of Device
		
		:param if_type: The spcific type of interface, such as 40GE.
		:type  if_type: str	
		"""	
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)

		

class Huawei(Device):
	"""
	Huwei Switch SSH Handler, with simple functions, such as login, show config, exce commands.
	
	"""
	
	def cleanup(self):
		"""Gracefully exit the SSH session."""
		self.write_channel("quit" + self.RETURN)
		
	def session_preparation(self):
		"""Prepare the session after the connection has been established."""
		self._test_channel_read(pattern=r'[<>\[\]]')
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
		self.write_channel(self.normalize_cmd('save'))
		self.read_until_prompt(pattern='\[Y/N\]', timeout=2)
		self.write_channel(self.normalize_cmd('y'))
		output = self.read_until_prompt(timeout=5)
		if 'successfully' in output:
			return True
		return False
	
	
	def current_config(self, command="display current-configuration", section=None, delay_factor=1, timeout=None):
		"""
		Get current config of Device.
		:param section: The spcific part config, such as aaa,bgp, ospf. etc.
		:type  section: str
		
		"""
		if section is not None:
			command = command + ' configuration ' + section
			
		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)	
		
		
	def interface_config(self, command="display current-configuration interface", interface=None, if_type=None, 
								delay_factor=1, timeout=None):
		"""
		Get current interface config of Device.
		
		:param interface: The spcific interface config, such as Eth1/1. Only one interface supported once.
		:type  interface: str
		
		"""
		return super(Huawei, self).interface_config(command=command, interface=interface, if_type=if_type, \
													delay_factor=delay_factor, timeout=timeout)
		

	def macaddress_table(self, command="display mac-address", vlan=None, interface=None, delay_factor=1, timeout=None):
		"""
		Get MacAddress Tables of Device
		
		:param vlan: The spcific vlan mac, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's mac, Only one interface supported once.
		:type  interface: str 
		"""
		return super(Huawei, self).macaddress_table(command=command, vlan=vlan, interface=interface, \
													delay_factor=delay_factor, timeout=timeout)
		

	def arp_table(self, command="display arp", vlan=None, interface=None, ipaddr=None, delay_factor=1, timeout=None):
		"""
		Get ARP Tables of Device
		
		:param vlan: The spcific vlan arp, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's arp, Only one interface supported once.
		:type  interface: str
		
		:param ipaddr: The spcific ip's arp, Only one ip supported once.
		:type  ipaddr: str
		
		"""
		_cmd = ''
		if vlan is not None:
			_cmd = ' vlan ' + str(vlan) + ' interface vlan ' + str(vlan)
			
		if interface is not None:
			_cmd = ' interface ' + interface
			
		if ipaddr is not None:
			_cmd = ' | in ' + ipaddr
			
		command += _cmd

		return self.send_command(command=command, delay_factor=delay_factor, timeout=timeout)
				
		
	def interface_brief(self, command="display interface brief", if_type=None, delay_factor=1, timeout=None):
		"""
		Get interface brief info of Device
		
		:param if_type: The spcific type of interface, such as 40GE.
		:type  if_type: str	
		"""	
		return super(Huawei, self).interface_brief(command=command, if_type=if_type, delay_factor=delay_factor,\
												   timeout=timeout)
		

		
class H3C(Huawei):
	"""
	H3C SSH Switch Handler, with simple functions, such as login, show config, exce commands.
	Most functions like Huawei Switch/Router.
	"""
	
	def session_preparation(self):
		"""Prepare the session after the connection has been established."""
		self._test_channel_read(pattern=r'[<>\[\]]')
		self.set_base_prompt()
		self.disable_paging(command="screen-length disable")
		# Clear the read buffer
		time.sleep(.3 * self.global_delay_factor)
		self.clear_buffer()
		
	def save_config(self, delay_factor=1):
		"""Save current running congfig to startup file, use switch's default command."""
		delay_factor = self.select_delay_factor(delay_factor)
		time.sleep(delay_factor * .1)
		self.clear_buffer()
		self.write_channel(self.normalize_cmd('save force'))
		output = self.read_until_prompt(timeout=5)
		if 'successfully' in output:
			return True
		return False

	def arp_table(self, command="display arp", vlan=None, interface=None, ipaddr=None, delay_factor=1, timeout=None):
		"""
		Get ARP Tables of Device
		
		:param vlan: The spcific vlan arp, Only one vlan supported once.
		:type  vlan: str or int 
		
		:param interface: The spcific interface's arp, Only one interface supported once.
		:type  interface: str
		
		:param ipaddr: The spcific ip's arp, Only one ip supported once.
		:type  ipaddr: str
		
		"""
			
		return super(Huawei, self).arp_table(command=command, vlan=vlan, interface=interface, ipaddr=ipaddr, delay_factor=delay_factor,\
											 timeout=timeout)		
	