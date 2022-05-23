# Introduction to Hacking Library

The goal of this library is to create an archive of useful tools and how to use them, mostly for:

- Hacking
- Pentests 
- Security

Remember, this is only a guide, use the knowledge here wisely and at your own risk.

Have fun!

# Tools 

## Arp

Using Arp protocol you can either scan your local network to discover hosts, revealing their MAC addresses and 
internet adapter manufacturer:

> sudo arp-scan --interface=eth0 --localnet

or try to guess the OS of the hosts with:

> sudo arp-fingerprint -l