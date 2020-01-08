from socket import AF_INET, socket
from pyroute2 import IPRoute, IPDB, netlink
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

class simplified_client_socket():
	def __init__(self, target, port, *args, **kwargs):
		self.data = b''
		self.data_pos = 0
		self._poll = epoll()
		self.target = target
		self.port = port
		try:
			self.socket = socket()
			self.socket.connect((self.target, self.port))
			self._poll.register(self.socket.fileno(), EPOLLIN | EPOLLHUP)
		except:
			self.socket = None

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self._poll.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def recv(self, buffert=8192):
		if not self.socket:
			try:
				self.socket = socket()
				self.socket.connect((self.target, self.port))
				self._poll.register(self.socket.fileno(), EPOLLIN | EPOLLHUP)
			except:
				self.socket = None
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
			try:
				self.socket = socket()
				self.socket.connect((self.target, self.port))
				self._poll.register(self.socket.fileno(), EPOLLIN | EPOLLHUP)
			except:
				self.socket = None
				return None

		if type(data) != bytes: data = bytes(data, 'UTF-8')
		self.socket.send(data)

class threaded(Thread):
	def __init__(self, callback=None, start_callback=None, *args, **kwargs):
		if not 'worker_id' in kwargs: kwargs['worker_id'] = randint(1000, 9999)
		Thread.__init__(self)
		self.args = args
		self.kwargs = kwargs
		self.pid = None
		self.exit_code = None
		self.started = time.time()
		self.ended = None
		self.worker_id = kwargs['worker_id']
		self.trace_log = b''
		self.status = 'starting'

		self.callback = callback
		self.start_callback = start_callback

		user_catalogue = '/home/anton'
		self.cwd = f"{user_catalogue}/.cache/vmmanger/workers/{kwargs['worker_id']}/"
		self.cmd = None

	def start_thread(self, cmd, *args, **kwargs):
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

class Switch():
	""" Creates a bridge with no firewall rules, allowing all traffic to flow"""
	def __init__(self, ifname=None, *args, **kwargs):
		if 'name' in kwargs: ifname = kwargs['name']
		if 'interface' in kwargs: ifname = kwargs['interface']
		if not ifname: ifname = 'switch0'

		with IPRoute() as ip:
			switch_lookup = ip.link_lookup(ifname=ifname)
			if not switch_lookup:
				ip.link('add', ifname=ifname, kind='bridge')
				switch_lookup = ip.link_lookup(ifname=ifname)
			self.index = switch_lookup[0]

			for interface in args:
				interface_index = ip.link_lookup(ifname=interface)[0]
				if interface_index:
					ip.link("set", index=interface_index, master=self.index)

	def connect(self, what, *args, **kwargs):
		if what != int: what = ip.link_lookup(ifname=what)[0]
		ip.link("set", index=what, master=self.index)

	def delete(self, *args, **kwargs):
		#for port in self.ports:
		#	port.delete()

		with IPRoute() as ip:
			ip.link("del", index=self.index)

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
		if not 'input' in kwargs: kwargs['input'] = None

		with IPRoute() as ip:
			trunk = ip.link_lookup(ifname=kwargs['trunk'])
			if not trunk:
				raise ValueError(f'Router() can not find trunk interface {kwargs["trunk"]}, is physically inserted?')
			self.trunk_index = trunk[0]

			bridge_lookup = ip.link_lookup(ifname=kwargs['ifname'])
			if not bridge_lookup:
				ip.link('add', ifname=kwargs['ifname'], kind='bridge')
				self.index = ip.link_lookup(ifname=kwargs['ifname'])[0]
			else:
				self.index = bridge_lookup[0]

			if kwargs['input'] is None:
				kwargs['input'] = NetworkPipe(f'{kwargs["ifname"]}-p0', f'{kwargs["ifname"]}-sink0')

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
		kwargs['input'].connect(what)
		#ip.link("set", index=what, master=self.index)

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
				print(f'[N] {source} and {target} already exists, wrapping them.')
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

	def connect(self, what, *args, **kwargs):
		ip.link("set", index=what, master=self.ports['source'])

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

	def eject(self):
		pass

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

class Machine(threaded, simplified_client_socket):
	""" A place holder for a KVM state"""
	# https://qemu.weilnetz.de/doc/qemu-doc.html
	# https://github.com/cirosantilli/linux-cheat/blob/master/qemu.md
	def __init__(self, *args, **kwargs):
		threaded.__init__(self)
		if not 'harddrives' in kwargs: kwargs['harddrives'] = Harddrive()
		if not 'nics' in kwargs: kwargs['nics'] = [NetworkPipe()]
		if not 'cd' in kwargs: kwargs['cd'] = None
		if not 'name' in kwargs: kwargs['name'] = 'Machine0'
		if not 'monitor' in kwargs: kwargs['monitor'] = ('localhost', 4444) # -monitor telnet::444,server,nowait / -qmp for control mode
		if not 'memory' in kwargs: kwargs['memory'] = 4096
		if not 'efi' in kwargs: kwargs['efi'] = True
		if not 'monitor_port' in kwargs: kwargs['monitor_port'] = 4000

		if not 'display' in kwargs: kwargs['display'] = None # = '-nographic'

		if type(kwargs['harddrives']) != list: kwargs['harddrives'] = [kwargs['harddrives']]
		if type(kwargs['nics']) != list: kwargs['nics'] = [kwargs['nics']]

		for key, val in kwargs.items():
			self.__dict__[key] = val

		self.alive = True

		self.setName(kwargs['name'])
		simplified_client_socket.__init__(self, '127.0.0.1', self.monitor_port)

	def __repr__(self, *args, **kwargs):
		return f'<Machine(name={self.name}, cd={self.cd}, hdd={self.harddrives}, nics={self.nics})>'

	def is_alive(self, *args, **kwargs):
		pass

	def start_vm(self, *args, **kwargs):
		params = '-enable-kvm -machine q35,accel=kvm -device intel-iommu'
		params += f' -cpu host'
		if self.display is None:
			params += f' -display none'
		else:
			raise ValueError('Machine() Non-non-graphical mode is not supported yet.')
		params += f' -m {self.memory}'
		if self.cd:
			params += f" -drive id=cdrom0,if=none,format=raw,readonly=on,file={self.cd.filename}"
			params += " -device virtio-scsi-pci,id=scsi0"
			params += " -device scsi-cd,bus=scsi0.0,drive=cdrom0,bootindex=1"

		for harddrive in self.harddrives:
			params += f" -drive file={harddrive.filename},format=qcow2" # TODO: get this string from the Harddrive() + get format

		if self.efi:
			params += f" -drive if=pflash,format=raw,readonly,file=/usr/share/ovmf/x64/OVMF_CODE.fd"
			params += f" -drive if=pflash,format=raw,readonly,file=/usr/share/ovmf/x64/OVMF_VARS.fd"

		params += f' -monitor tcp:127.0.0.1:{self.monitor_port},server,nowait'

		#for nic in self.nics:
		#	As for manual steps,  they might look like this:
		#	# ip link add qemu1-h type veth peer name qemu1-g
		#	# ip link set qemu1-g netns qemu1
		#	# ip netns exec qemu1 ip link add link qemu1-g type macvtap mode vepa
		#	# ip netns exec qemu1 ip link set macvtap0 up

		#	To pass macvtap to qemu, look at /dev/tapX device and redirect it to qemu.

		#	For example:

		#	# ip netns exec qemu1 /opt/qemu/current/bin/qemu-system-x86_64 -enable-kvm \
		#	-m 1024 -netdev tap,id=netdev1,vhost=on,fd=6 6<>/dev/tap6 \
		#	-device virtio-net-pci,id=nic1,addr=0x0a,mac=02:d6:c0:2c:ab:a1,netdev=netdev1

		self.start_thread(f'qemu-system-x86_64 {params}')
		print(f'[N] {self} has started, qemu interface at 127.0.0.1:{self.monitor_port}')

	def is_running(self, *args, **kwargs):
		return self.alive

	def stop(self, *args, **kwargs):
		pass
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

	del(interfaces['wlp0s20f3']['raw_data'])
	print('WiFi interface:', json.dumps(interfaces['wlp0s20f3'], indent=4, default=lambda o: str(o)))

	router = Router('ens4u1')
	router.delete()

	switch = Switch()
	switch.delete()

	harddrive = Harddrive(filename='test0.qcow2')
	harddrive.snapshot()

	harddrive.wipe(snapshots_only=True)

	archlinux_live_cd = CD('/home/anton/archinstall_iso/out/archlinux-2019.11.29-x86_64.iso', readonly=True)

	machine = Machine(harddrives=harddrive, nics=switch, cd=archlinux_live_cd)
	machine.start_vm()

	while machine.is_alive() or machine.exit_code is None:
		qemu_output = machine.recv()
		if qemu_output:
			print(qemu_output.decode('UTF-8'))
			if b'monitor -' in qemu_output:
				machine.screenshot()
			elif b'screendump ' in qemu_output:
				machine.send('quit\n')
		time.sleep(1)

	print('Machine has terminated.')