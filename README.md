# Vmanager
Virtual Manager - To manage KVM based machines

# What is it?

It's essentially just a fancy wrapper around `iproute2` and `qemu` for KVM.<br>
It has hooks *(functions)* for creating virtual harddrives, cd-roms, network interfaces, switches, routers.

It separates each virtual machine into network namespaces, attaches zero or more layer 2 network interfaces to the machine. These network interfaces have two endpoints, one going into the machine and one that you can plug into any network device *(virtual or physical)*.

It also supports snapshotting live running machines, harddrives, dump memory and screenshot machines.<br>
All machines run in a headless mode by default, screenshots can be taken and stored some where, as well as sending keystrokes and mouse actions to the machines.

# Documentation

This documentation will be moved to readthedocs or something.

| Class/Function  | Description |
| ------------- | ------------- |
| vmanager.interfaces  | A curated list over all physical (hosts) NIC's *(Contains: IP's, routes, gateways)* |
| vmanager.routes  | A list of all physical routes  |
| vmanager.sys_command  | Runs a shell command on the host machine  |
| vmanager.Interface  | Each interface gets wrapped in this helper class in order to make life easier, by accessing `Interface.ip` for instance to get the interface's IP address, or `Interface.routes`. You can also do `Interface.up` to bring up a interface. |
| <strike>vmanager.Bond()</strike>  | <strike>Used to aggregate multiple NIC's into one logical interface</strike> *(TODO)* |
| vmanager.Switch  | Creates a virtual switch *(Currently creates a bridge where other interfaces can be slaved to, in order to emulate a "switch")*  |
| vmanager.Router  | Creates a router *(bridge)* interface with one trunk interface and one LAN port. Used to tie together physical interfaces to the virtual realm and give machines access to the outside world.  |
| vmanager.VirtualNic  | Creates a virtual `VETH` interface with a `port<--->sink` setup. If `namespace=<name>` is given, the `sink` end of the pipe is moved into a namespace, and is given a `macvtap` interface that can be used to give to a virtual machine to enable layer2 traffic.  |
| vmanager.CD  | A wrapper around ISO's, virtual machines uses `cd.qemu_string` wrapper to get the string representation to give a VM a CD that's useable  |
| vmanager.Harddrive  | Same as `CD`, but supports `.snapshots`, `.create`, `.wipe([snapshots_only=False])` and <strike>`.resize`</strike> as well as `.qemu_string`.  |
| vmanager.Machine  | The main class really, it sets up a KVM enabled machine that can use NIC's, HDD's, CD's and other stuff. Use `.send()` to talk to the QEMU console, for instance `.send(b'ctrl-alt-f2')` switches to TTY2 on a Unix machine. Full documentation on the different functions can be found below in a separate table for `Machine`  |

### Machine

| Functions  | Description |
| ------------- | ------------- |
| vmanager.Machine()  | `harddrives=` takes `Harddrive` as a object or a list of objects. `nics` same thing, but takes `int` to define how many interfaces or a list of `VirtualNic`'s, `cd` takes one `CD` as argument. `memory` takes a `int` representing MB in size of RAM allocated. `monitor_port` will be the TCP port that `qemu` will listen to in order for you to connect (This automatically happens when setting up the `Machine()` instance. But you can use it to define a pre-defined port.)  |
| Machine.is_alive  | Returns weither or not the machine is running.  |
| Machine.start_vm  | Starts the VM *(grabs `qemu_string` from attached resources.)*  |
| Machine.stop  | Stops the VM forcefully. |
| Machine.freeze  | Freezes the VM (useful for snapshotting etc)  |
| Machine.unfreeze  | Unfreezes the VM  |
| Machine.snapshot  | Snapshots the machine and it's harddrives.  |
| Machine.load_snapshot  | Restores a previously taken snapshot  |
| Machine.delete_snapshot  | Removes a stored snapshot.  |
| Machine.increase_ram  | Tries to resize the RAM and inform the host  |
| Machine.resize_harddrive  | Calls the `Harddrive().resize()` function |
| Machine.change_boot_device  | Changes boot priority, useful right before reboot.  |
| Machine.create_chardev  | <strike>Creates a chardev</strike>  |
| Machine.eject  | Calls `CD.eject()` in order to eject the CD.  |
| Machine.migrate  | Migrates the machine to another KVM instance.  |
| Machine.mouse_move  | Moves the mouse cursor inside the machine to `x, y`  |
| Machine.mouse_click  | Clicks `button=1` where the mouse cursor currently is in the machine.  |
| Machine.add_nic  | Add another NIC, if the guest supports it, it's hot swapped in.  |
| Machine.del_nic  | Removes a NIC.  |
| Machine.screenshot  | Takes a screendump of the machine and stores it in `filename=<full path>`  |
| Machine.send_key  | Sends a key combination to the QEMU console, which sends it into the machine. `send_key("ctrl-alt-del")` for instance.  |
| Machine.nic_state  | Turns the NIC on or off in the QEMU instance, doesn't affect physical link states on the host. If you want to change physical states, do `vmanager.interfaces["name"].down()` for instance. |

# Requirements

 * python-iproute2
 * qemu *(tools such as `qemu-img` etc)*

# Supports

 * Routers *(bridge with a outbound interface slaved as trunk, and LAN port is a VETH interface)*
 * Switches *(normal bridge utility interface)*
 * Virtual Hard drives with snapshots *(Currently only qcow2 format)*
