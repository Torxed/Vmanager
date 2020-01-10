# Vmanager
Virtual Manager - To manage KVM based machines

# What is it?

It's essentially just a fancy wrapper around `iproute2` and `qemu` for KVM.<br>
It has hooks *(functions)* for creating virtual harddrives, cd-roms, network interfaces, switches, routers.

It separates each virtual machine into network namespaces, attaches zero or more layer 2 network interfaces to the machine. These network interfaces have two endpoints, one going into the machine and one that you can plug into any network device *(virtual or physical)*.

It also supports snapshotting live running machines, harddrives, dump memory and screenshot machines.<br>
All machines run in a headless mode by default, screenshots can be taken and stored some where, as well as sending keystrokes and mouse actions to the machines.

# Requirements

 * python-iproute2
 * qemu *(tools such as `qemu-img` etc)*

# Supports

 * Routers *(bridge with a outbound interface slaved as trunk, and LAN port is a VETH interface)*
 * Switches *(normal bridge utility interface)*
 * Virtual Hard drives with snapshots *(Currently only qcow2 format)*
