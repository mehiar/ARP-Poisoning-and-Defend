# ARP-Poisoning-and-Defend
This project provides two tools:
1. **ARP Poisoning Tool:** allows you to poison the ARP cache of a host connected to your local network using three different methods.
2. **ARP Defend Tool:** allows you to detect and log such ARP poisoning attacks.

## Prerequisite
* [java sdk](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
* [libpcap](http://www.tcpdump.org/)

## How to Run The Poisoning Program
1. Make sure that you have the latest version of libpcap and java sdk.
2. From the command line, change the current directory to the directory of the 'poison.class' ﬁle.
3. Execute the following command: 
`sudo java poison -ipsrc=<spoofed IP source> -ipdst=<destination IP>
-hardsrc=<source MAC address> -harddst=<destination MAC address> -intf=<0 for eth0 or 1
for wlan0>`
The source IP and destination IP are mandatory ﬁelds, all others are optional.  The
default value for the interface is eth0, for the hardsrc is the interface’s MAC and broadcast for the
harddst.

## How to Run the Defend Program
1. Make sure that you have the latest version of libpcap and java sdk.
2. From the command line, change the current directory to the directory of the 'defend.class' file.
3. Execute the following command: `sudo java defend -intf=<0 for eth0 or 1 for wlan0> -timeout=<timeout
in seconds>` Both ﬁelds are optional and the default value for interface is eth0 and the default for
timeout is 10 seconds.

## ARP Cache Poisoning Methods
Three methods were used to poison the cache:

1. **ARP  request  attack:**  an ARP request packet is sent with the spoofed IP (i.e the stolen IP
address)  as  the  source  IP  and  with  the  MAC  address  of  the  attacker  as  the  hardware  source
address.   The destination IP address is that of the machine to be poisoned.   If no destination
hardware address is speciﬁed, the packet is broadcasted.
2. **ARP reply attack:** an ARP reply packet is sent with the spoofed IP (i.e the stolen IP address)
as the source IP and with the MAC address of the attacker as the hardware source address.  The
reply is broadcasted.
3. **ARP gratuitous attack:** an ARP reply packet is boadcasted with the spoofed IP as the source
and destination protocol address.

## Detection Approach
The detection approach maintains a list of all the IPs and their associated MAC addresses. This is done
by creating an entry for each received ARP packet with a new IP source.  Once a new entry is created,
an ARP request is sent to the source address of the received packet to make sure that this address is
reachable and that no other machine has the same IP address (to detect ARP poisoning attacks).  In
the normal case, an ARP reply is received with the same source IP and source MAC address as the
stored entry. An attack will be ﬂagged if we receive an ARP reply with a diﬀerent MAC address. If no
ARP reply is received then this means that this IP address is unreachable and that it is possible that
the attacker is trying to claim that he has a diﬀerent non-existing IP address. In this approach, no false
alarms should be generated. Also, the ammount of traﬃc created by this defence mechanism is not large
since we don’t send ARP requests if the entry already exists. The defence system maitains a log ﬁle that
contains all attacks.

## Documentation
The '[summary.pdf](https://github.com/mehiar/ARP-Poisoning-and-Defend/blob/master/Doc/summary.pdf)' file contains snapshots that demonstrate how our tools work.
