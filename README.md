# Live Packet Capture

## Lab #1

### Traffic Monitoring & Analysis

## Context

The goal of this lab was to implement a C program that uses ``libpcap`` to collect live traffic from a network interface in our computer. The program had to collect only traffic with destination port ``80`` or ``443``. 

For each collected packet, the program had to show in the screen its timestamp, its source IP address, its destination IP address and the length of the packet in the wire. The snaplen had to be configured to the minimum value that allows us to get the required information.

## How to run?

First `Npcap` and its SDK need to be installed:

````bash
sudo apt install libpcap0.8 libpcap0.8
````

Verify `pcap.h` file header is in the `IncludePath`:

````bash
/usr/include/
/usr/include/pcap/
````

The code can now be compiled using:

````bash
gcc -o LiveCapture packet_capture.c -l pcap
````

Then executed:

````bash
$ sudo ./LiveCapture
Listening for packets...

Interface: eth0
Timestamp: 14/11/2023 09h01min 08s.579335
Source IP: 172.26.210.75
Dest.  IP: 52.168.112.67
Packet Length: 2922 bytes
--------------------------------
Interface: eth0
Timestamp: 14/11/2023 09h01min 08s.579341
Source IP: 172.26.210.75
Dest.  IP: 52.168.112.67
Packet Length: 2922 bytes
--------------------------------
Interface: eth0
Timestamp: 14/11/2023 09h01min 08s.579553
Source IP: 172.26.210.75
Dest.  IP: 52.168.112.67
Packet Length: 1884 bytes
--------------------------------
````
