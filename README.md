# tcpparse

This tool is used for simple analysis of pcap file and extraction of main fields for the automatic test program to identify the test results.

## The help information
```
./tcpparse -h

Parse pcap file to extract ip, port, checksum, payload, etc.

Usage: tcpparse [OPTIONS] filename

OPTIONS:
  -h, --help     Display help and exit.
  -i, --index    Target packet index in pcap file, default is 1.
  -l, --length   Length of whole packet.
      --sm       Source mac.
      --dm       Destination mac.
  -t, --ethtype  Ethernet type.
  -s, --sip      Source ip.
  -d, --dip      Destination ip.
  -p, --proto    Protocol in ip header.
      --sp       Source port if tcp and udp, return 0 for other protocol.
      --dp       Destination port if tcp and udp, return 0 for other protocol.
      --checkl3  Verify ip header checksum, return 0 if success, or return 1.
      --checkl4  Verify udp/tcp checksum, return 0 if success, or return 1.
      --pl       Print payload.
```

## Select the packet serial number. The serial number here is the number in wireshark. If keep empty, the first message is selected by default. 
```
./tcpparse --sm ./tcpdump.pcap
00:50:56:8e:9a:c8
./tcpparse -i 1 --sm ./tcpdump.pcap
00:50:56:8e:9a:c8
```

## Get the source and destination mac, and ethernet type from pcap file
```
./tcpparse --sm ./tcpdump.pcap
00:50:56:8e:9a:c8
./tcpparse --dm ./tcpdump.pcap
c8:4c:75:02:01:bf
./tcpparse --ethtype ./tcpdump.pcap
0800
```

## Get the source and destination ip address, protocol and port from pcap file
```
./tcpparse -s ./tcpdump.pcap
128.224.97.79
./tcpparse -d ./tcpdump.pcap
172.25.48.32
./tcpparse -p ./tcpdump.pcap
6
./tcpparse --sp ./tcpdump.pcap
445
./tcpparse --dp ./tcpdump.pcap
49795
```

## Validate L3(IP header) checksum, and L4(UDP or TCP) checksum. 0 means good, 1 means bad.
```
./tcpparse --checkl3 ./tcpdump.pcap
0
./tcpparse --checkl4 ./tcpdump.pcap
1
./tcpparse -i 79 --checkl4 ./tcpdump.pcap
0
```

## Contact us
lijingrui@gmail.com