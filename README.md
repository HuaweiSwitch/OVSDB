## Overview

Huawei CloudEngine series data center switches use Huawei's next-generation Versatile Routing Platform (VRP) operating system to provide full openness in addition to stable, reliable, and secure high-performance switching services.

The switches support Linux containers (LXC) technology, which enables the Open vSwitch Database Management Protocol (OVSDB) plugin to be easily installed on the switches for seamless connection with the VMware NSX network virtualization platform. The NSX platform creates a visual model of the entire network and enables customers to create and deploy any network topology in seconds. With the NSX platform, virtual networks can be deployed and managed through software programming, making customer networks open and flexible. The NSX platform can be used with Huawei CloudEngine switches to construct elastic, virtualized, and efficient cloud computing networks. 

Huawei CloudEngine switches support the standard Virtual Extensible LAN (VXLAN) protocol and can act as VXLAN gateways for traditional servers, connecting them to the VMware VXLAN network. Based on the vSphere 6 platform, VMware NSX uses the OVSDB protocol to deliver OpenFlow tables to Huawei CloudEngine data center switches and centrally controls hardware and software virtual tunnel end points (VTEPs). Collaboration of Huawei CloudEngine switches and VMware NSX enables efficient communication between traditional servers and VXLAN servers. This solution combines the high performance of hardware equipment and flexibility of software, while providing high scalability. 

The code is ported from [Open vSwitch 2.5.0](https://github.com/openvswitch/ovs)

##The main components of this distribution are:

- ovsdb-server - a OVSDB server to save the configuration from NSX controller.
- ovsdb-client - a OVSDB client to communicate between NSX controller and Huawei switches.
- ovs-pki - a utility for creating and managing the public-key infrastructure for NSX controller communication.
- vtep-ctl - a tool to show the OVSDB data.
- huaweiswitch-key - a key management tools to encrypt user key.
 
##Implement guide:

Refer to [CloudEngine Hardware Gateway Integration with VMware NSX-V 6.2.4 — Implementation Guide](http://e.huawei.com/en/marketing-material/global/products/enterprise_network/ce_switches/cloudengine%20switches/20161209085719)
 
##References

* [VMware Knowleadge Base](https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&docType=kc&externalId=2148611&sliceId=1&docTypeID=DT_KB_1_1&dialogID=409793307&stateId=0%200%20409801236)
