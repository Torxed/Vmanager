from socket import AF_INET, socket, AF_UNIX, SOCK_DGRAM
from pyroute2 import IPRoute, IPDB, netlink, NetNS, netns
from collections import OrderedDict as OD
from random import randint # TODO: Replace
from threading import Thread, enumerate as tenum
from subprocess import Popen, STDOUT, PIPE
from glob import glob
from select import epoll, EPOLLIN, EPOLLHUP
import pty
import shlex
import time
import ipaddress
import shutil
import os
import json #DEB

# Great information source:
#   https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking/
#   https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/
#   https://linux-blog.anracom.com/tag/linux-bridge-linking/
#   https://unix.stackexchange.com/questions/272146/packets-not-moving-through-linux-ethernet-bridge
#   - https://serverfault.com/questions/540671/filter-broadcast-traffic-in-a-bridge-port
#   - http://www.microhowto.info/troubleshooting/troubleshooting_ethernet_bridging_on_linux.html
#   http://hicu.be/bridge-vs-macvlan

## Build a cache with our interfaces before we begin setting things up.
default_routes = {}
interfaces = {}
gateways = {}
routes = {}

machines = {}
nics = {}
routers = {}
switches = {}
harddrives = {}
cds = {}

tmp_mapper = {} # Maps IP -> Interface

def update_interface_cache():
	# IPv4Address('192.0.2.6') in IPv4Network('192.0.2.0/28')

	with IPRoute() as ip:
		with IPDB() as ipdb:
			for link in ip.get_links():
				ifname = link.get_attr('IFLA_IFNAME')

				#print(f'{ifname}:')
				#print(json.dumps(link, indent=4, default=lambda o: str(o)))
				#print(json.dumps(ipdb.by_name[ifname], indent=4, default=lambda o: str(o)))

				interfaces[ifname] = {
					'ip' : list(ipdb.by_name[ifname]['ipaddr']),
					'mac' : link.get_attr('IFLA_ADDRESS'), # / ipdb['address']
					'state' : link['state'],
					'gateway' : None,
					'routes' : [],
					'connected_to' : [],
					'raw_data' : {
						'link' : link,
						'ip' : ipdb.by_name[ifname]
					}
				}

				if interfaces[ifname]['mac'][:5] == 'fe:01':
					_type = interfaces[ifname]['mac'].split(':')[2]
					print(ifname, _type)
					if _type == '00':
						print(ifname, 'is a switch')
						switches[ifname] = Switch(ifname=ifname, **interfaces[ifname])
					elif _type == '01':
						print(ifname, 'is a router')
						routers[ifname] = Router(ifname=ifname, **interfaces[ifname])
					#elif _type == '02':
					#	interfaces[ifname] = Bridge(ifname=ifname, **interfaces[ifname])
					elif _type == '03':
						interfaces[ifname] = None # This is a sink to another network interface
					else:
						print(ifname, 'is a Vnic')
						nics[ifname] = VirtualNic(ifname=ifname, **interfaces[ifname])
					
					del(interfaces[ifname])
				else:
					interfaces[ifname] = Interface(ifname=ifname, **interfaces[ifname])
				
				for ip_addr in ipdb.by_name[ifname]['ipaddr']:
					tmp_mapper[ip_addr[0]] = ifname

		for route in ip.get_default_routes():
			gateways[route.get_attr('RTA_GATEWAY')] = route
			default_routes[route.get_attr('RTA_GATEWAY')] = {'priority' : route.get_attr('RTA_PRIORITY'), 'raw_data' : route}

		for route in ip.get_routes():
			route_dest = route.get_attr('RTA_DST')
			gateway = route.get_attr('RTA_GATEWAY')
			preferred_source = route.get_attr('RTA_PREFSRC')

			if gateway:
				gateways[gateway] = route
			
			routes[route_dest] = {'source' : preferred_source, 'raw_data' : route, 'gateway' : gateway}
			
			if gateway and not route_dest and not preferred_source:
				# Default route, try to find the preferred source
				for interface in interfaces:
					for ip_info in interfaces[interface].ip:
						interface_subnet = ipaddress.ip_network(f'{ip_info[0]}/{str(ip_info[1])}', strict=False)
						if ipaddress.IPv4Address(gateway) in interface_subnet:
							interfaces[interface]['gateway'] = gateway
							break

			for interface in interfaces:
				for ip_info in interfaces[interface]['ip']:
					try:
						if ipaddress.IPv4Address(ip_info[0]) == ipaddress.IPv4Address(preferred_source):
							interfaces[interface]['routes'].append(route_dest)
					except ipaddress.AddressValueError:
						continue # IPv6 address, TODO: Implement support for IPv6

def sys_command(cmd, opts=None, *args, **kwargs):
	if not opts: opts = {}
	if 'debug' in opts:
		print('[!] {}'.format(cmd))
	handle = Popen(cmd, shell='True', stdout=PIPE, stderr=STDOUT, stdin=PIPE, **kwargs)
	output = b''
	while handle.poll() is None:
		data = handle.stdout.read()
		if len(data):
			if 'debug' in opts:
				print(data.decode('UTF-8'), end='')
		#	print(data.decode('UTF-8'), end='')
			output += data
	data = handle.stdout.read()
	if 'debug' in opts:
		print(data.decode('UTF-8'), end='')
	output += data
	handle.stdin.close()
	handle.stdout.close()
	return output

def generate_mac(*args, **kwargs):
	if not 'device' in kwargs: kwargs['device'] = None
	# https://serverfault.com/a/40720/150015

	prefix = 254 # FE
	version = 1
	if kwargs['device'] and kwargs['device'] == 'switch':
		kwargs['device'] = 0
	elif kwargs['device'] and kwargs['device'] == 'router':
		kwargs['device'] = 1
	elif kwargs['device'] and kwargs['device'] == 'bridge':
		kwargs['device'] = 2
	elif kwargs['device'] and kwargs['device'] == 'sink':
		kwargs['device'] = 3
	else:
		kwargs['device'] = randint(10, 255)
	random1 = randint(0, 255)
	random2 = randint(0, 255)
	random3 = randint(0, 255)

	mac = ':'.join([hex(x)[2:].zfill(2) for x in [prefix, version, kwargs['device'], random1, random2, random3]])
	print('Generated new mac:', mac)
	return mac

class simplified_client_socket():
	def __init__(self, target, *args, **kwargs):
		self.data = b''
		self.data_pos = 0
		self._poll = epoll()
		self.target = target
		self.connect()

	def connect(self, *args, **kwargs):
		try:
			self.socket = socket(AF_UNIX)
			self.socket.connect(self.target)
			self._poll.register(self.socket.fileno(), EPOLLIN | EPOLLHUP)
		except FileNotFoundError:
			self.socket = None
			return None
		return True

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self._poll.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def recv(self, buffert=8192):
		if not self.socket:
			if not self.connect():
				return None

		if self.poll(fileno=self.socket.fileno()):
			try:
				d = self.socket.recv(buffert)
			except ConnectionResetError:
				d = ''
			if len(d) == 0:
				self.close()
				return None
			self.data += d
			self.data_pos += len(d)
			return self.data[self.data_pos-len(d):]
		return None

	def close(self):
		self.socket.close()
		return True

	def send(self, data):
		if not self.socket:
			if not self.connect():
				return None

		if type(data) != bytes: data = bytes(data, 'UTF-8')
		try:
			self.socket.send(data)
		except BrokenPipeError:
			pass

class threaded(Thread):
	def __init__(self, callback=None, start_callback=None, *args, **kwargs):
		if not 'worker_id' in kwargs: kwargs['worker_id'] = randint(1000, 9999)
		Thread.__init__(self)
		self.args = args
		self.kwargs = kwargs
		self.pid = None
		self.exit_code = -1
		self.started = time.time()
		self.ended = None
		self.worker_id = kwargs['worker_id']
		self.trace_log = b''
		self.status = 'starting'
		self.alive = None

		self.callback = callback
		self.start_callback = start_callback

		user_catalogue = '/home/anton'
		self.cwd = f"{user_catalogue}/.cache/vmmanger/workers/{kwargs['worker_id']}/"
		self.cmd = None

	def start_thread(self, cmd, *args, **kwargs):
		self.alive = True
		self.raw_cmd = cmd
		self.start()

	def __repr__(self, *args, **kwargs):
		return self.trace_log.decode('UTF-8')

	def dump(self):
		return {
			'status' : self.status,
			'worker_id' : self.worker_id,
			'worker_result' : self.trace_log.decode('UTF-8'),
			'started' : self.started,
			'ended' : self.ended,
			'started_pprint' : '{}-{}-{} {}:{}:{}'.format(*time.localtime(self.started)),
			'ended_pprint' : '{}-{}-{} {}:{}:{}'.format(*time.localtime(self.ended)) if self.ended else None,
			'exit_code' : self.exit_code
		}

	def run(self, *args, **kwargs):
		main = None
		for t in tenum():
			if t.name == 'MainThread':
				main = t
				break

		if not main:
			print('Main thread not existing')
			return

		self.cmd = shlex.split(self.raw_cmd)
		self.exec_dir = f'{self.cwd}/{os.path.basename(self.cmd[0])}_workingdir'

		if not self.cmd[0][0] == '/':
			o = sys_command('/usr/bin/which {}'.format(self.cmd[0])).strip()
			self.cmd[0] = o.decode('UTF-8')

		if not os.path.isdir(self.exec_dir):
			os.makedirs(self.exec_dir)

		if self.start_callback: self.start_callback(self, *args, **kwargs)
		
		self.status = 'running'
		old_dir = os.getcwd()
		os.chdir(self.exec_dir)
		self.pid, child_fd = pty.fork()
		if not self.pid: # Child process
			# Replace child process with our main process
			os.execv(self.cmd[0], self.cmd)
		os.chdir(old_dir)

		poller = epoll()
		poller.register(child_fd, EPOLLIN | EPOLLHUP)

		self.alive = True
		last_trigger_pos = 0
		while self.alive and main and main.is_alive():
			for fileno, event in poller.poll(0.1):
				try:
					output = os.read(child_fd, 8192).strip()
					self.trace_log += output
				except OSError:
					self.alive = False
					break

				lower = output.lower()
				broke = False
				if 'events' in self.kwargs:
					for trigger in list(self.kwargs['events']):
						if trigger.lower() in self.trace_log[last_trigger_pos:].lower():
							trigger_pos = self.trace_log[last_trigger_pos:].lower().find(trigger.lower())

							last_trigger_pos = trigger_pos
							os.write(child_fd, self.kwargs['events'][trigger])
							del(self.kwargs['events'][trigger])
							broke = True
							break

					if broke:
						continue

					## Adding a exit trigger:
					if len(self.kwargs['events']) == 0:

						if bytes(f']$'.lower(), 'UTF-8') in self.trace_log[0-len(f']$')-5:].lower():
							self.alive = False
							break

		self.status = 'done'
		self.alive = False

		try:
			self.exit_code = os.waitpid(self.pid, 0)[1]
		except ChildProcessError:
			try:
				self.exit_code = os.waitpid(child_fd, 0)[1]
			except ChildProcessError:
				self.exit_code = 1

		self.ended = time.time()
		with open(f'{self.cwd}/trace.log', 'wb') as fh:
			fh.write(self.trace_log)

		if self.callback:
			self.callback(self, *self.args, **self.kwargs)

		if self.exit_code != 0:
			print(f'Process {self.cmd[0]} has exited with {self.exit_code}.')
			print(self.trace_log)

		return self.exit_code

class Interface():
	def __init__(self, *args, **kwargs):
		## Some aliases for ifname:
		if 'name' in kwargs: kwargs['ifname'] = kwargs['name']
		if 'interface' in kwargs: kwargs['ifname'] = kwargs['interface']
		## --
		if not 'mac' in kwargs: kwargs['mac'] = None
		if not 'ip' in kwargs: kwargs['ip'] = []
		if not 'state' in kwargs: kwargs['state'] = 'Unknown'
		if not 'subnet' in kwargs: kwargs['subnet'] = None
		if not 'routes' in kwargs: kwargs['routes'] = []
		if not 'gateway' in kwargs: kwargs['gateway'] = None
		if not 'connected_to' in kwargs: kwargs['connected_to'] = []
		if not 'ifname' in kwargs: raise KeyError('Interface() needs a ifname.')

		for key, val in kwargs.items():
			if key == 'ip': continue # Sets up later
			self.__dict__[key] = val

		with IPRoute() as ip:
			self.index = ip.link_lookup(ifname=kwargs['ifname'])[0]

		self._ip = kwargs['ip']

	def up(self, *args, **kwargs):
		print(f'[N] Interface() up on {self}')
		with IPRoute() as ip:
			ip.link("set", index=self.index, state="up")
		self.state = 'up'

	def down(self, *args, **kwargs):
		print(f'[N] Interface() down on {self}')
		with IPRoute() as ip:
			ip.link("set", index=self.index, state="down")
		self.state = 'down'

	def master(self, ifname, *args, **kwargs):
		print(f'[N] Interface() setting master on {self} to {ifname}')
		with IPRoute() as ip:
			ip.link("set",
				index=self.index,
				master=ip.link_lookup(ifname=ifname)[0])

	@property
	def ip(self, *args, **kwargs):
		for ip in self._ip:
			yield ip

	@ip.setter
	def ip(self, address, netmask):
		with IPRoute() as ip:
			ip.addr('add', index=self.index, address=address, mask=netmask)
			self._ip.append((address, netmask))
		return True

	def __getitem__(self, key, *args, **kwargs):
		if key == 'ip': return iter(self.ip)
		return self.__dict__[key]

	def __setitem__(self, key, val, *args, **kwargs):
		self.__dict__[key] = val

	def __delitem__(self, key, *args, **kwargs):
		del(self.__dict__[key])

	def __iter__(self, *args, **kwargs):
		for item in self.__dict__:
			yield item

	def __repr__(self, *args, **kwargs):
		addresses = ', '.join(sorted(['/'.join([str(i) for i in x]) for x in list(self.ip)]))
		return f"{self.ifname}@[state='{self['state']}', ip=({addresses})]"

	def __dump__(self, *args, **kwargs):
		return {
			'ip' : self._ip,
			'mac' : self.mac,
			'state' : self.state,
			'gateway' : self.gateway,
			'routes' : self.routes,
			'connected_to' : self.connected_to
		}

class Bond():
	""" Not 007, but close. It's a aggregated NIC with multiple outputs.
	Great for increasing speed if the host machine has multiple interfaces"""
	def __init__(self, *args, **kwargs):
		pass
		"""
		ip link add bond1 type bond miimon 100 mode balance-alb
		ip link set eth0 master bond1
		ip link set eth1 master bond1
		"""

class Switch():
	""" Creates a bridge with no firewall rules, allowing all traffic to flow"""
	def __init__(self, ifname=None, *args, **kwargs):
		if 'name' in kwargs: ifname = kwargs['name']
		if 'interface' in kwargs: ifname = kwargs['interface']
		if not 'ip' in kwargs: kwargs['ip'] = None
		if not 'mac' in kwargs: kwargs['mac'] = generate_mac(*args, **{'device' : 'switch', **kwargs})
		if not 'state' in kwargs: kwargs['state'] = 'up'
		if not ifname:
			index = 0
			ifname = f'switch{index}'
			with IPRoute() as ip:
				while ip.link_lookup(ifname=ifname):
					index += 1
					ifname = f'switch{index}'
		else:
			with IPRoute() as ip:
				index = ip.link_lookup(ifname=ifname)
				if index:
					print(f'[N] Switch {ifname} already exists, wrapping it.')
					print('TODO: Get the connections (master/slave) of the switch.')

		for key, val in kwargs.items():
			self.__dict__[key] = val

		self.ifname = ifname
		self.connections = {}

		with open('/proc/sys/net/bridge/bridge-nf-call-iptables', 'w') as iptables:
			iptables.write('0\n')

		with IPRoute() as ip:
			switch_lookup = ip.link_lookup(ifname=ifname)
			if not switch_lookup:
				ip.link('add', ifname=ifname, kind='bridge', address=kwargs['mac'])
				switch_lookup = ip.link_lookup(ifname=ifname)
			self.index = switch_lookup[0]

			for interface in args:
				interface_index = ip.link_lookup(ifname=interface)[0]
				if interface_index:
					ip.link("set", index=interface_index, master=self.index)
				self.connections[interface] = True

			ip.link('set', index=self.index, state='up')

		switches[self.ifname] = {
			'ip' : self.ip,
			'mac' : self.mac, # / ipdb['address']
			'state' : self.state,
			'gateway' : None,
			'routes' : [],
			'connected_to' : []
		}

	def connect(self, what, *args, **kwargs):
		print(f'[N] {self} is enslaving {what}.')
		if type(what) != int: what = ip.link_lookup(ifname=what)[0]

		with IPRoute() as ip:
			ip.link("set", index=what, master=self.index)

	def delete(self, *args, **kwargs):
		#for port in self.ports:
		#	port.delete()

		with IPRoute() as ip:
			ip.link("del", index=self.index)

	def __repr__(self, *args, **kwargs):
		return f'Switch(name={self.ifname}, ports={list(self.connections.keys())})'

class Router():
	""" Creates a bridge <-> interface link with a in and out side"""
	def __init__(self, *args, **kwargs):
		# Some aliases for trunk:
		if 'of' in kwargs: kwargs['trunk'] = kwargs['of']
		if 'output' in kwargs: kwargs['trunk'] = kwargs['output']
		# ----
		if not 'mac' in kwargs: kwargs['mac'] = generate_mac(*args, **{'device' : 'router', **kwargs})
		if not 'ip' in kwargs: kwargs['ip'] = None
		if not 'state' in kwargs: kwargs['state'] = 'up'
		if not 'trunk' in kwargs:
			if len(args) and args[0]:
				kwargs['trunk'] = args[0]
			else:
				raise KeyError('Router() needs a trunk interface.')

		if not 'ifname' in kwargs:
			index = 0
			ifname = f'router{index}'
			with IPRoute() as ip:
				while ip.link_lookup(ifname=ifname):
					index += 1
					ifname = f'router{index}'
			kwargs['ifname'] = ifname
		else:
			with IPRoute() as ip:
				index = ip.link_lookup(ifname=kwargs["ifname"])
				if index:
					print(f'[N] Router {kwargs["ifname"]} already exists, wrapping it.')
					print('TODO: Get the connections (master/slave) of the router.')
		if not 'input' in kwargs: kwargs['input'] = None
		for key, val in kwargs.items():
			self.__dict__[key] = val

		print(f'[N] Router() is using "{self.trunk}" as trunk')

		with IPRoute() as ip:
			trunk = ip.link_lookup(ifname=kwargs['trunk'])
			if not trunk:
				raise ValueError(f'Router() can not find trunk interface {kwargs["trunk"]}, is physically inserted?')
			self.trunk_index = trunk[0]

			with open('/proc/sys/net/bridge/bridge-nf-call-iptables', 'w') as iptables:
				iptables.write('0\n')

			bridge_lookup = ip.link_lookup(ifname=kwargs['ifname'])
			if not bridge_lookup:
				ip.link('add', ifname=kwargs['ifname'], kind='bridge', address=self.mac)
				self.index = ip.link_lookup(ifname=kwargs['ifname'])[0]
			else:
				self.index = bridge_lookup[0]

			if kwargs['input'] is None:
				kwargs['input'] = VirtualNic(f'{kwargs["ifname"]}-p0', sink=f'{kwargs["ifname"]}-sink0', namespace=False)

			print(f'[N] Router() is enslaving {kwargs["trunk"]} and {kwargs["ifname"]}-sink0')

			print(kwargs['input'].ports)
			ip.link("set", index=self.trunk_index, master=self.index) # Slave trunk to this router (bridge)
			ip.link("set", index=kwargs['input'].ports['sink'], master=self.index) # Slave the routers port-0 sink to this router

			kwargs['input'].up()
			ip.link('set', index=self.index, state='up')

			interface = ip.get_addr(index=self.trunk_index)
			if interface:
				#print(interface[0])
				#print('Trunk IP:', interface[0].get_attr('IFA_ADDRESS'))
				ip.flush_addr(self.trunk_index)
				sys_command(f'dhclient -v {kwargs["ifname"]}')

		routers[self.ifname] = {
			'ip' : self.ip,
			'mac' : self.mac, # / ipdb['address']
			'state' : self.state,
			'gateway' : kwargs['trunk'],
			'routes' : [],
			'connected_to' : kwargs['input'].ports['sink_name']
		}

	def delete(self, *args, **kwargs):
		self.input.delete()
		with IPRoute() as ip:
			ip.link("del", index=self.index)

	def connect(self, what, target, *args, **kwargs):
		what = f'{self.ifname}-{what}'
		if type(what) != int:
			with IPRoute() as ip:
				source_index = ip.link_lookup(ifname=what)[0]
		print(f'[N] Router() is connecting {what} to {target}')
		target.connect(source_index, target)
		#ip.link("set", index=what, master=self.index)

	def nat(self, *args, **kwargs):
		pass

	def not_nat(self, *args, **kwargs):
		pass

class NetworkNameSpace():
	""" Creates a network namespace and keeps track of it's interfaces """
	def __init__(self, *args, **kwargs):
		pass

class VirtualNic():
	def __init__(self, source=None, *args, **kwargs):
		if not source and 'ifname' in kwargs: source=kwargs['ifname']
		if not 'sink' in kwargs: kwargs['sink'] = f'{source}-sink'
		if not 'namespace' in kwargs: kwargs['namespace'] = None
		if not 'mac' in kwargs: kwargs['mac'] = generate_mac(*args, **{'device' : 'vnic', **kwargs})
		if not 'sink_mac' in kwargs: kwargs['sink_mac'] = generate_mac(*args, **{'device' : 'sink', **kwargs})
		if not 'ip' in kwargs: kwargs['ip'] = None
		if not 'state' in kwargs: kwargs['state'] = 'Unknown'
		if not 'gateway' in kwargs: kwargs['gateway'] = None
		if not 'routes' in kwargs: kwargs['routes'] = [],
		if not 'connected_to' in kwargs: kwargs['connected_to'] = []

		print(f'[N] Setting up VNic({source} <--> {kwargs["sink"]})')

		for key, val in kwargs.items():
			self.__dict__[key] = val

		with IPRoute() as ip:
			try:
				ip.link('add', ifname=source, kind='veth', peer=self.sink, address=self.mac)
				source_index = ip.link_lookup(ifname=source)[0]
				sink_index = ip.link_lookup(ifname=self.sink)[0]
				ip.link('set', index=sink_index, address=self.sink_mac)
			except netlink.exceptions.NetlinkError:
				print(f'[N] {source} and {self.sink} already exists, wrapping them.')
				source_index = ip.link_lookup(ifname=source)[0]
				sink_index = ip.link_lookup(ifname=self.sink)[0]

		with IPRoute() as ip:
			self.ports = {
				'source' : source_index,
				'source_name' : source,
				'sink' : sink_index,
				'sink_name' : kwargs['sink']
			}

			if 'namespace' in kwargs and kwargs['namespace']:
				self.set_namespace(kwargs['namespace'])

		nics[self.ports['source_name']] = self
		nics[self.ports['sink_name']] = self

	def __getitem__(self, key, *args, **kwargs):
		if key == 'ip': return iter(self.ip)
		return self.__dict__[key]

	def __setitem__(self, key, val, *args, **kwargs):
		self.__dict__[key] = val

	def __delitem__(self, key, *args, **kwargs):
		del(self.__dict__[key])

	def __iter__(self, *args, **kwargs):
		for item in self.__dict__:
			yield item

	def __repr__(self, *args, **kwargs):
		sink_repr = self.ports["sink_name"]
		if self.namespace: sink_repr += '@'+self.namespace
		return f'VNic("{self.ports["source_name"]} <--> {sink_repr}")'

	def delete(self, *args, **kwargs):
		with IPRoute() as ip:
			ip.link("del", index=self.ports['source'])

	def up(self, *args, **kwargs):
		print(f'[N] VNic() up on {self}')
		self.state = True
		with IPRoute() as ip:
			ip.link('set', index=self.ports['source'], state='up')
			if not self.namespace:
				ip.link('set', index=self.ports['sink'], state='up')
			else:
				o = sys_command(f"ip netns exec {self.namespace} /bin/bash -c 'ip link set dev {self.ports['sink_name']} up'")

	def down(self, *args, **kwargs):
		print(f'[N] VNic() down on {self}')
		self.state = False
		with IPRoute() as ip:
			ip.link('set', index=self.ports['source'], state='down')
			if not self.namespace:
				ip.link('set', index=self.ports['sink'], state='down')
			else:
				o = sys_command(f"ip netns exec {self.namespace} /bin/bash -c 'ip link set dev {self.ports['sink_name'].split('@',1)[0]} down'")

	def connect(self, what, target=None, *args, **kwargs):
		if target:
			print(f'[N] {self} is enslaving {what} to {self.ports["source_name"]}')
			with IPRoute() as ip:
				if type(what) != int: what = ip.link_lookup(ifname=what)[0]
				ip.link("set", index=what, master=self.ports['source'])
		else:
			print(f'[N] {self} is connecting to {what}')
			what.connect(self.ports['source'])

	def set_namespace(self, namespace, *args, **kwargs):
		print(f'[N] VNic setting namespace "{namespace}" for {self.ports["sink_name"]}(index: {self.ports["sink"]})')

		try:
			netns.create(namespace)
		except FileExistsError:
			pass # Already exists, we can use it below.

		with IPRoute() as ip:
			try:
				ip.link('set', index=self.ports['sink'], net_ns_fd=namespace)
			except:
				print(f'[N] VNic can\'t change namespace for {self.ports["sink_name"]}. Most likely because it\'s already enslaved to a namespace.')

		# Because NetNS() or IPRoute() or IPDB() appears to be lacking the support to create
		# interfaces within a namespace, we'll have to revert to shell-commands.
		o = sys_command(f'ip netns exec {namespace} ip link add link {self.ports["sink_name"]} type macvtap mode bridge')
		if len(o) <= 0:
			o = sys_command(f"ip netns exec {namespace} /bin/bash -c 'ip link set macvtap0 address {self.mac} up'")
		else:
			print(f'[E] Could not create a virtual macvtap for {self.ports["sink_name"]}')
			print(o)

		self.tap_interface = None
		o = sys_command(f"ip netns exec {namespace} /bin/bash -c 'ls /sys/class/net/macvtap0/'")
		for file in o.decode('UTF-8').split('\n'):
			if file[:3] == 'tap':
				self.tap_interface = file
				break

		if not self.tap_interface:
			print('[E] VirtualNic() could not create a virtual macvtap for the tap interface.')
#		with NetNS(namespace) as ns:
#			with IPDB(nl=ns) as ip:
#				ip.link('add', ifname=self.ports['sink'], kind='macvtap') #mode=vepa | bridge(default)

		self.namespace = namespace

	def qemu_string(self, *args, **kwargs):
		if self.namespace and not self.tap_interface:
			print('[E] Can not use this NIC, namespace given but no macvtap located.')
			return None

		if self.namespace:
			#	tap6 \
			#	
			params = f' -netdev tap,id=netdev1,vhost=on,fd=6 6<>/dev/{self.tap_interface}'
			params += f' -device virtio-net-pci,id=nic1,addr=0x0a,mac={self.mac},netdev=netdev1'
		else:
			params = f' -netdev tap,ifname={self.tap_interface},id=network0,script=no,downscript=no'
			params += f' -device i82559b,netdev=network0,mac={self.mac}'

		return params

class CD():
	def __init__(self, *args, **kwargs):
		if not 'filename' in kwargs:
			if len(args) and args[0]:
				kwargs['filename'] = args[0]
			else:
				raise KeyError('CD() needs a filename.')
		if not 'readonly' in kwargs: kwargs['readonly'] = True
		if not os.path.isfile(kwargs['filename']):
			raise ValueError(f'CD() can\'t access {args["filename"]}')

		for key, val in kwargs.items():
			self.__dict__[key] = val

		cds[self.filename] = self

	def __repr__(self, *args, **kwargs):
		return f'CD({os.path.basename(self.filename)})'

	def eject(self):
		pass

	def qemu_string(self, boot_index, *args, **kwargs):
		params = f" -drive id=cdrom0,if=none,format=raw,readonly=on,file={self.filename}"
		params += f" -device virtio-scsi-pci,id=scsi0"
		params += f" -device scsi-cd,bus=scsi0.0,drive=cdrom0,bootindex={boot_index}"
		return params

class Harddrive():
	def __init__(self, *args, **kwargs):
		if not 'filename' in kwargs: kwargs['filename'] = 'harddrive0.qcow2'
		if not 'format' in kwargs: kwargs['format'] = 'qcow2'
		if not 'snapshots' in kwargs:
			kwargs['snapshots'] = OD()
			for file in glob(f'{kwargs["filename"]}.snap*'):
				kwargs['snapshots'][file] = None
		if not 'size' in kwargs: kwargs['size'] = 5 # in GB

		kwargs['filename'] = os.path.abspath(kwargs['filename'])
		# qemu-img create -f qcow2 disk.qcow2 5GB
		# qemu-img create -o backing_file=disk.qcow2,backing_fmt=qcow2 -f qcow2 snapshot0.cow

		for key, val in kwargs.items():
			self.__dict__[key] = val

		if not os.path.isfile(self.filename):
			if not self.create(**kwargs):
				raise ValueError(f'Could not create virtual harddrive image: {self.filename}')

		harddrives[kwargs['filename']] = self

	def __repr__(self, *args, **kwargs):
		return f'HDD({os.path.basename(self.filename)})'

	def create(self, *args, **kwargs):
		if not 'format' in kwargs: kwargs['format'] = self.format
		if not 'size' in kwargs: kwargs['size'] = self.size
		if not 'filename' in kwargs: raise KeyError('No filename given to Harddrive().create()')
		if kwargs['filename'][0] != '/': kwargs['filename'] = os.path.abspath(kwargs['filename'])

		o = sys_command('qemu-img create -f qcow2 {filename} {size}G'.format(**kwargs))
		if not os.path.isfile(kwargs['filename']):
			return None
		
		return True

	def snapshot(self, *args, **kwargs):
		if not 'machine' in kwargs:
			if len(self.snapshots):
				latest = list(self.snapshots)[-1]
				latest_num_pos = latest.find('.snap')
				filename = latest[0:latest_num_pos]
				num = int(latest[latest_num_pos+5:])

				snapshot_what = latest
				snapshot_to = f'{filename}.snap{num+1}'

			else:
				snapshot_what = self.filename
				snapshot_to = f'{self.filename}.snap0'

			shutil.copy2(snapshot_what, snapshot_to)
			self.snapshots[snapshot_to] = None
		else:
			pass
			# qemu: snapshot_blkdev -n device [new-image-file] [format]

	def wipe(self, *args, **kwargs):
		for snapshot in self.snapshots:
			os.remove(snapshot)

		if not 'snapshots_only' in kwargs:
			os.remove(self.filename)

	def resize(self, new_size, *args, **kwargs):
		pass

	def qemu_string(self, boot_index, *args, **kwargs):
		#return f" -drive file={self.filename},format={self.format}"
		params = f" -drive id=hdd0,if=none,media=disk,snapshot=off,format={self.format},file={self.filename}"
		params += f" -device virtio-scsi-pci,id=scsi1"
		params += f" -device scsi-hd,bus=scsi1.0,drive=hdd0,bootindex={boot_index}"
		return params

class Machine(threaded, simplified_client_socket):
	""" A place holder for a KVM state"""
	# https://qemu.weilnetz.de/doc/qemu-doc.html
	# https://github.com/cirosantilli/linux-cheat/blob/master/qemu.md
	def __init__(self, *args, **kwargs):
		threaded.__init__(self)
		if not 'harddrives' in kwargs: kwargs['harddrives'] = Harddrive()
		if not 'nics' in kwargs: kwargs['nics'] = 0
		if not 'cd' in kwargs: kwargs['cd'] = None
		if not 'name' in kwargs: kwargs['name'] = 'Machine0'
		if not 'namespace' in kwargs: kwargs['namespace'] = kwargs['name'] # Each virtual machine will end up in a namespace.
		if not 'monitor' in kwargs: kwargs['monitor'] = ('localhost', 4444) # -monitor telnet::444,server,nowait / -qmp for control mode
		if not 'memory' in kwargs: kwargs['memory'] = 4096
		if not 'efi' in kwargs: kwargs['efi'] = True
		if not 'monitor_port' in kwargs: kwargs['monitor_port'] = 4000

		machines[kwargs['name']] = self

		if not 'display' in kwargs: kwargs['display'] = None # = '-nographic'
		self.setName(kwargs['name'])

		if type(kwargs['harddrives']) in (int, float):
			harddrives = []
			for index in range(kwargs['harddrives']):
				hdd = Harddrive(filename=f'test{index}.qcow2')
				harddrives.append(hdd)
			kwargs['harddrives'] = harddrives
		if type(kwargs['harddrives']) != list: kwargs['harddrives'] = [kwargs['harddrives']]
		if type(kwargs['nics']) in (int, float):
			# Non specific nics given, just the ammount that we want
			machine_nics = []
			for index in range(kwargs['nics']):
				nic = VirtualNic(f"{kwargs['name']}-p{index}", sink=f"{kwargs['name']}-sink{index}", namespace=kwargs['namespace'])
				nic.up()
				machine_nics.append(nic)
			kwargs['nics'] = machine_nics
		if type(kwargs['nics']) != list: kwargs['nics'] = [kwargs['nics']]

		if kwargs['cd'] and type(kwargs['cd']) != CD and os.path.isfile(kwargs['cd']):
			kwargs['cd'] = CD(kwargs['cd'])

		for nic in kwargs['nics']:
			if not nic.namespace == kwargs['namespace']:
				nic.set_namespace(kwargs['namespace'])

		for key, val in kwargs.items():
			self.__dict__[key] = val

		simplified_client_socket.__init__(self, f'/tmp/{kwargs["name"]}_socket')

	def __repr__(self, *args, **kwargs):
		return f'Machine(name={self.name}, cd={self.cd}, hdd\'s={self.harddrives}, nics={self.nics} monitor=/tmp/{self.name}_socket)'

	def delete(self, *args, **kwargs):
		self.stop_vm()
		for nic in self.nics:
			nic.delete()
		netns.remove(self.namespace)

	def start_vm(self, *args, **kwargs):
		self.exit_code = -1
		self.alive = None
		params = '-enable-kvm'
		params += ' -machine q35,accel=kvm'
		params += ' -device intel-iommu'
		params += ' -cpu host'

		if self.display is None:
			params += f' -display none'
		
		params += f' -m {self.memory}'
		if self.cd:
			params += self.cd.qemu_string(boot_index=1)

		for harddrive in self.harddrives:
			params += harddrive.qemu_string(boot_index=2)

		if self.efi:
			params += f" -drive if=pflash,format=raw,readonly,file=/usr/share/ovmf/x64/OVMF_CODE.fd"
			params += f" -drive if=pflash,format=raw,readonly,file=/usr/share/ovmf/x64/OVMF_VARS.fd"

		# Add a monitor port to the qemu console, so that we can control this VM after startup.
		#params += f' -monitor tcp:127.0.0.1:{self.monitor_port},server,nowait'
		params += f' -monitor unix:/tmp/{self.name}_socket,server,nowait'

		for nic in self.nics:
			params += nic.qemu_string()

		self.start_thread(f'/bin/bash -c \'ip netns exec {self.namespace} qemu-system-x86_64 {params}\'')
		print(f'[N] {self} has started.')

		time.sleep(1)
		for nic in self.nics:
			nic.up()

	def is_running(self, *args, **kwargs):
		return self.exit_code is None or self.alive

	def stop_vm(self, *args, **kwargs):
		self.exit_code = -1
		self.send(b'quit\n') # see below
		# qemu: stop / system_powerdown

	def freeze(self, *args, **kwargs):
		pass
		# qemu: stop

	def unfreeze(self, *args, **kwargs):
		pass
		# qemu: cont   (not continue)

	def snapshot(self, *args, **kwargs):
		self.freeze()
		# qemu: savevm [tag]
		for harddrive in self.harddrives:
			harddrive.snapshot()
		self.unfreeze()

	def load_snapshot(self, tag, *args, **kwargs):
		pass
		# qemu: loadvm tag

	def delete_snapshot(self, tag, *args, **kwargs):
		pass
		# qemu: delvm tag

	def increase_ram(self, new_size, *args, **kwargs):
		pass

	def resize_harddrive(self, target, new_size, *args, **kwargs):
		self.harddrives[target].resize(new_size)

	def change_boot_device(self, new_device, *args, **kwargs):
		pass

	def create_chardev(self, *args, **kwargs):
		pass
		## -chardev tty,id=id,path=path
		## -chardev stdio,id=id[,signal=on|off]
		## -chardev socket,id=id[,TCP options or unix options][,server][,nowait][,telnet][,websocket][,reconnect=seconds][,tls-creds=id][,tls-authz=id]
	
	def dump_memory(self, *args, **kwargs):
		if not 'filename' in kwargs: kwargs['filename'] = self.name + '.mem_dump0'
		pass

	def eject(self, *args, **kwargs):
		self.cd.eject()

	def migrate(self, *args, **kwargs):
		pass

	def mouse_move(self, *args, **kwargs):
		pass

	def mouse_click(self, *args, **kwargs):
		pass

	def add_nic(self, *args, **kwargs):
		pass

	def del_nic(self, *args, **kwargs):
		pass

	def screenshot(self, *args, **kwargs):
		self.send(f'screendump {os.getcwd()}/testing.png\n')
		# qemu: screendump filename [device [head]]

	def send_key(self, key_string, *args, **kwargs):
		pass
		# qemu: sendkey keys [hold_ms]

	def nic_state(self, state, *args, **kwargs):
		pass
		# qemu: set_link name on|off

	def delete_nic(self, *args, **kwargs):
		self.del_nic(*args, **kwargs)
	def remove_nic(self, *args, **kwargs):
		self.del_nic(*args, **kwargs)


def create_virtual_harddrive(*args, **kwargs):
	pass

def create_virtual_machine(*args, **kwargs):
	pass

def create_virtual_switch(*args, **kwargs):
	pass

def create_virtual_router(*args, **kwargs):
	pass


if __name__ == '__main__':
	update_interface_cache()

	del(interfaces['wlp0s20f3']['raw_data']) # Clear stuff we don't need for printing debug output.
	print('[N] WiFi interface:', json.dumps(interfaces['wlp0s20f3'], indent=4, default=lambda o: str(o)))

	# Set up a route out to the internet, for test purposes.
	router = Router('ens4u1')
	switch = Switch()

	# Connect routers port 0 to the switch.
	router.connect('p0', switch)

	# Set up some paraphernalia that the virtual machine can use.
	harddrive = Harddrive(filename='test0.qcow2')
	archlinux_live_cd = CD('/home/anton/archinstall_iso/out/archlinux-2019.11.29-x86_64.iso', readonly=True)

	# Test the snapshot functionality, then wipe the snapshot :)
	harddrive.snapshot()
	harddrive.wipe(snapshots_only=True)

	# Start the virtual machine.
	machine = Machine(harddrives=harddrive, nics=1, cd=archlinux_live_cd)
	machine.nics[0].connect(switch)

	machine.start_vm()

	while machine.is_alive():
		qemu_output = machine.recv()
		if qemu_output:
#			print(qemu_output.decode('UTF-8'))
			if b'monitor -' in qemu_output:
				time.sleep(25)
				print('[N] Taking a screenshot.')
				machine.screenshot()
			elif b'screendump ' in qemu_output:
				print('[N] Sending quit to the machine.')
				machine.stop_vm()
		time.sleep(1)

	print('Machine has terminated.')
	machine.delete()
	router.delete()
	switch.delete()