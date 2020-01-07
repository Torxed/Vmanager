from socket import AF_INET
from pyroute2 import IPRoute, IPDB, netlink
from collections import OrderedDict as OD
from random import randint # TODO: Replace
from threading import Thread
from subprocess import Popen, STDOUT, PIPE
from glob import glob
import ipaddress
import shutil
import os
import json #DEB

# Great information source:
#   https://developers.redhat.com/blog/2018/10/22/introduction-to-linux-interfaces-for-virtual-networking/
#   https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/

## Build a cache with our interfaces before we begin setting things up.
default_routes = {}
interfaces = {}
gateways = {}
routes = {}

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

class _spawn(Thread):
	def __init__(self, cmd, callback=None, start_callback=None, *args, **kwargs):
		if not 'worker_id' in kwargs: kwargs['worker_id'] = randint(1000, 9999)
		Thread.__init__(self)
		self.cmd = shlex.split(cmd)
		self.args = args
		self.kwargs = kwargs
		self.callback = callback
		self.pid = None
		self.exit_code = None
		self.started = time.time()
		self.ended = None
		self.worker_id = kwargs['worker_id']
		self.trace_log = b''
		self.status = 'starting'

		user_catalogue = '/home/anton'
		self.cwd = f"{user_catalogue}/.cache/vmmanger/workers/{kwargs['worker_id']}/"
		self.exec_dir = f'{self.cwd}/{basename(self.cmd[0])}_workingdir'

		if not self.cmd[0][0] == '/':
			o = b''.join(sys_command('/usr/bin/which {}'.format(self.cmd[0])).exec())
			self.cmd[0] = o.decode('UTF-8')

		if not isdir(self.exec_dir):
			os.makedirs(self.exec_dir)

		if start_callback: start_callback(self, *args, **kwargs)
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

	def run(self):
		main = None
		for t in tenum():
			if t.name == 'MainThread':
				main = t
				break

		if not main:
			print('Main thread not existing')
			return
		
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

		alive = True
		last_trigger_pos = 0
		while alive and main and main.isAlive():
			for fileno, event in poller.poll(0.1):
				try:
					output = os.read(child_fd, 8192).strip()
					self.trace_log += output
				except OSError:
					alive = False
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
							alive = False
							break

		self.status = 'done'

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

		worker_history[self.worker_id] = self.dump()

		if 'dependency' in self.kwargs:
			## If this had a dependency waiting,
			## Start it since there's no hook for this yet, the worker has to spawn it's waiting workers.
			module = self.kwargs['dependency']['module']
			print(self.cmd[0],'fullfills a dependency:', module)
			dependency_id = self.kwargs['dependency']['id']
			dependencies[module][dependency_id]['fullfilled'] = True
			dependencies[module][dependency_id]['spawn'](*dependencies[module][dependency_id]['args'], **dependencies[module][dependency_id]['kwargs'], start_callback=_worker_started_notification)

		if self.callback:
			self.callback(self, *self.args, **self.kwargs)

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
		with IPRoute() as ip:
			ip.link("set", index=self.index, state="up")

	def down(self, *args, **kwargs):
		with IPRoute() as ip:
			ip.link("set", index=self.index, state="down")

	def master(self, ifname, *args, **kwargs):
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

class Machine():
	""" A place holder for a KVM state"""
	def __init__(self, *args, **kwargs):
		pass

class Switch():
	""" Creates a bridge with no firewall rules, allowing all traffic to flow"""
	def __init__(self, ifname=None, *args, **kwargs):
		if 'name' in kwargs: ifname = kwargs['name']
		if 'interface' in kwargs: ifname = kwargs['interface']
		if not ifname: ifname = 'switch0'

		with IPRoute() as ip:
			ip.link('add', ifname=ifname, kind='bridge')
			self.index = ip.link_lookup(ifname=ifname)[0]

			for interface in args:
				interface_index = ip.link_lookup(ifname=interface)[0]
				if interface_index:
					ip.link("set", index=interface_index, master=self.index)

	def connect(self, what, *args, **kwargs):
		if what != int: what = ip.link_lookup(ifname=what)[0]
		ip.link("set", index=what, master=self.index)

class Router():
	""" Creates a bridge <-> interface link with a in and out side"""
	def __init__(self, *args, **kwargs):
		# Some aliases for trunk:
		if 'of' in kwargs: kwargs['trunk'] = kwargs['of']
		if 'output' in kwargs: kwargs['trunk'] = kwargs['output']
		# ----
		if not 'trunk' in kwargs:
			if len(args) and args[0]:
				kwargs['trunk'] = args[0]
			else:
				raise KeyError('Router() needs a trunk interface.')
		if not 'ifname' in kwargs: kwargs['ifname'] = 'router0'
		if not 'input' in kwargs: kwargs['input'] = NetworkPipe(f'{kwargs["ifname"]}-p0', f'{kwargs["ifname"]}-sink0')

		with IPRoute() as ip:
			ip.link('add', ifname=kwargs['ifname'], kind='bridge')
			self.index = ip.link_lookup(ifname=kwargs['ifname'])[0]
			self.trunk_index = ip.link_lookup(ifname=kwargs['trunk'])[0]
			ip.link("set", index=self.trunk_index, master=self.index) # Slave trunk to this router (bridge)
			ip.link("set", index=kwargs['input'].ports['target'], master=self.index) # Slave the routers port-0 sink to this router

		for key, val in kwargs.items():
			self.__dict__[key] = val

	def delete(self, *args, **kwargs):
		self.input.delete()
		with IPRoute() as ip:
			ip.link("del", index=self.index)

	def connect(self, what, *args, **kwargs):
		if what != int: what = ip.link_lookup(ifname=what)[0]
		ip.link("set", index=what, master=self.index)

	def nat(self, *args, **kwargs):
		pass

	def not_nat(self, *args, **kwargs):
		pass

class NetworkNameSpace():
	""" Creates a network namespace and keeps track of it's interfaces """
	def __init__(self, *args, **kwargs):
		pass

class NetworkPipe():
	""" Creates a vethX <-> vethY interface chain"""
	def __init__(self, source, target, *args, **kwargs):
		with IPRoute() as ip:
			try:
				ip.link('add', ifname=source, kind='veth', peer=target)
			except netlink.exceptions.NetlinkError:
				raise KeyError(f'NetworkPipe() says {source} or {target} already exists.')
			self.ports = {
				'source' : ip.link_lookup(ifname=source)[0],
				'target' : ip.link_lookup(ifname=target)[0]
			}
		"""
		ip link netns add net1
		ip link netns add net2
		ip link add veth1 netns net1 type veth peer name veth2 netns net2
		or without network namespaces:
		ip link add veth1 type veth peer name veth2
		"""

	def delete(self, *args, **kwargs):
		with IPRoute() as ip:
			ip.link("del", index=self.ports['source'])

class Harddrive():
	def __init__(self, *args, **kwargs):
		if not 'filename' in kwargs: kwargs['filename'] = 'harddrive0.qcow2'
		if not 'snapshots' in kwargs:
			kwargs['snapshots'] = OD()
			for file in glob(f'{kwargs["filename"]}.snap*'):
				kwargs['snapshots'][file] = None
		if not 'size' in kwargs: kwargs['size'] = 5 # in GB

		# qemu-img create -f qcow2 disk.qcow2 5GB
		# qemu-img create -o backing_file=disk.qcow2,backing_fmt=qcow2 -f qcow2 snapshot0.cow

		for key, val in kwargs.items():
			self.__dict__[key] = val

		if not os.path.isfile(self.filename):
			if not self.create(self.filename, self.size):
				raise ValueError(f'Could not create virtual harddrive image: {self.filename}')

	def create(self, filename, size, *args, **kwargs):
		o = sys_command(f'qemu-img create -f qcow2 {filename} {size}G')
		if not os.path.isfile(filename):
			return None
		return True

	def snapshot(self, *args, **kwargs):
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

	def wipe(self, *args, **kwargs):
		for snapshot in self.snapshots:
			os.remove(snapshot)

		if not 'snapshots_only' in kwargs:
			os.remove(self.filename)

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
	del(interfaces['wlp0s20f3']['raw_data'])
	print(json.dumps(interfaces['wlp0s20f3'], indent=4, default=lambda o: str(o)))

	router = Router('ens4u1')
	router.delete()

	harddrive = Harddrive(filename='test0.qcow2')
	harddrive.snapshot()

	harddrive.wipe(snapshots_only=True)

