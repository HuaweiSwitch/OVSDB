Overview

Open vSwitch is an open-source software switch designed to be used as a vswitch (virtual switch) in virtualized server environments.  A vswitch forwards traffic between different virtual machines (VMs) on the same physical host and also forwards traffic between VMs and the physical network.  Open vSwitch is open to programmatic extension and control using OpenFlow and the OVSDB (Open vSwitch Database) management protocol. It was designed to support distribution across multiple physical servers.

The main components of this distribution are:
 - ovs-vswitchd - a daemon that implements the switch, along with a companion Linux kernel module for flow-based switching.
 - ovsdb-server - a lightweight database server that ovs-vswitchd queries to obtain its configuration.
 - ovs-dpctl - a tool for configuring the switch kernel module.
 - Scripts and specs for building RPMs for Citrix XenServer and Red Hat Enterprise Linux. The XenServer RPMs allow Open vSwitch to be installed on a Citrix XenServer host as a drop-in replacement for its switch, with additional functionality.
 - ovs-vsctl - a utility for querying and updating the configuration of ovs-vswitchd.
 - ovs-appctl - a utility that sends commands to running Open vSwitch daemons. 
Provided tools are:
 - ovs-ofctl - a utility for querying and controlling OpenFlow switches and controllers.
 - ovs-pki - a utility for creating and managing the public-key infrastructure for OpenFlow switches.
 - A patch to tcpdump that enables it to parse OpenFlow messages.
 
Installation

Circumstance instruction:

This software runs in lxc environment which installed Debian openration system contained by CE switch.

Main steps:
 - Install CE switch with firmware which included lxc environment.
 - Pre-configure CE switch.
 - Install ovsdb in lxc.
 - Start ovsdb server.
 - Start ovsdb client.
 - Invoke configuration command.
 - 
Example usage

Start ovsdb-server before starting ovs-vswitchd itself:

$ ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
                     --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
                     --private-key=db:Open_vSwitch,SSL,private_key \
                     --certificate=db:Open_vSwitch,SSL,certificate \
                     --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                     --pidfile --detach
If you built Open vSwitch without SSL support, then omit --private-key, --certificate, and --bootstrap-ca-cert.

Start client monitoring:
$ ovsdb-client vtep monitor

Start client transacting:
$ ovsdb-client vtep transact

Connect to ssl with specified port:
$ vtep-ctl set-manager ssl:IP address:port

Configure the IP address of tunnel:
$ vtep-ctl set physical_switch swich_name tunnel_ips=tunnel IP address

References
[1] Open vSwitch:
    < http://openvswitch.org >

[2] Bugs report:
    < bugs@openvswitch.org >

