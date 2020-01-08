# Vmanager
Virtual Manager - To manage KVM based machines

# What is it?

It's essentially just a fancy wrapper around `iproute2` and `qemu` for KVM.<br>

# Requirements

 * python-iproute2
 * qemu *(tools such as `qemu-img` etc)*

# Supports

 * Routers *(bridge with a outbound interface slaved as trunk, and LAN port is a VETH interface)*
 * Switches *(normal bridge utility interface)*
 * Virtual Hard drives with snapshots *(Currently only qcow2 format)*
