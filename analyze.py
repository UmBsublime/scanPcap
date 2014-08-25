#!/usr/bin/env python

import dpkt
import socket
import sys
import os

import analyzeHttp as http
import analyzeDns as dns
import analyzeArp as arp

from math import trunc

class scan():

    def __init__(self, filename):

        self.filename = filename

        self.timeStart = 0
        self.timeEnd = 0

        self.counter=0
        self.ipcounter=0
        self.nonipcounter=0
        self.tcpcounter=0
        self.udpcounter=0
        self.arpcounter=0
        self.httpcounter=0
        self.httpscounter=0
        self.smtpcounter=0
        self.dhcpcounter=0
        self.ftpcounter=0
        self.sshcounter=0
        self.ntpcounter=0
        self.telnetcounter=0
        self.whoiscounter=0
        self.rsynccounter=0
        self.icmpcounter=0
        self.ipv6counter=0

        self.ethPacketList = []
        self.arpPacketList = []
        self.ipPacketList = []
        self.tcpPacketList = []
        self.udpPacketList = []

        self.subnets = {}

        # initialize counters
        self.setCounters()

        # plug-in analyzers
        self.http = http.analyzeHttp(self.tcpPacketList)
        self.dns = dns.analyzeDns(self.ethPacketList)
        self.arp = arp.analyzeArp(self.arpPacketList)

    def setCounters(self):
        # Packet processing loop
        capture = dpkt.pcap.Reader(open(self.filename,'rb'))
        #maxPacket = len(capture[0]-1)
        #self.timeStart = capture[ts][1]
        #self.timeEnd = capture[0][-1]
        tsCounter = 0
        for ts in capture:
            tsCounter += 1
        for ts,pkt in capture:
            self.counter+=1
            if self.counter == (tsCounter - 1):
                self.timeEnd = ts
            if self.counter == 1:
                self.timeStart = ts

            #print ts

            # Parse ethernet packet
            eth=dpkt.ethernet.Ethernet(pkt)
            self.ethPacketList.append(eth)
            ip=eth.data

            #check if IP packet or non-ip packet
            if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                self.ipcounter += 1
            else:
                self.nonipcounter += 1


            # IPV4 packets
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                self.ipPacketList.append(ip)

            # IPV6 packets
            if eth.type==dpkt.ethernet.ETH_TYPE_IP6:
                self.ipv6counter+=1

            # ARP packet
            elif eth.type==dpkt.ethernet.ETH_TYPE_ARP:
                self.arpPacketList.append(ip)
                self.arpcounter+=1

            # ICMP packets
            elif ip.p==dpkt.ip.IP_PROTO_ICMP:
                self.icmpcounter+=1

            # IPV4 packets
            elif eth.type==dpkt.ethernet.ETH_TYPE_IP:

                # Extract destination
                string = socket.inet_ntoa(ip.dst)
                address = '.'.join(string.split(".")[:2]) # ---->>>> Can easily change subnet statistic here
                if address in self.subnets: #increase count in dict
                    self.subnets[address] = self.subnets[address] + 1
                else: #insert key, value in dict
                    self.subnets[address] = 1

                # TCP packets
                if ip.p==dpkt.ip.IP_PROTO_TCP: #ip.p == 6:
                    self.tcpcounter+=1
                    tcp=ip.data
                    self.tcpPacketList.append(tcp)

                    # HTTP uses port 80
                    if tcp.dport == 80 or tcp.sport == 80:
                        self.httpcounter+=1

                    # HTTPS uses port 443
                    elif tcp.dport == 443 or tcp.sport == 443:
                        self.httpscounter+=1

                    # SSH uses port 22
                    elif tcp.dport == 22 or tcp.sport == 22:
                        self.sshcounter+=1

                    # SMTP uses port 25
                    elif tcp.dport == 25 or tcp.sport == 25:
                        self.smtpcounter+=1

                    # telnet uses port 23
                    elif tcp.dport == 23 or tcp.sport == 23:
                        self.telnetcounter+=1

                    # whois uses port 43
                    elif tcp.dport == 43 or tcp.sport == 43:
                        self.whoiscounter+=1

                    # rsync uses port 873
                    elif tcp.dport == 873 or tcp.sport == 873:
                        self.rsynccounter+=1

                    # FTP uses port 21
                    elif tcp.dport == 21 or tcp.sport == 21:
                        self.ftpcounter+=1

                # UDP packets
                elif ip.p==dpkt.ip.IP_PROTO_UDP: #ip.p==17:
                    self.udpcounter+=1
                    udp=ip.data
                    self.udpPacketList.append(udp)

                    # DHCP uses ports 67, 68
                    if udp.dport == 67 or udp.dport == 68:
                        self.dhcpcounter+=1

                    # NTP uses port 123
                    elif udp.dport == 123:
                        self.ntpcounter+=1

    def printConnections(self, v=False):

        tempFile = '.connections.tmp'
        counter = 0
        for ip in self.ipPacketList:
            counter += 1
            c = '' # connection
            if ip.p != dpkt.ip.IP_PROTO_ICMP and ip.p != dpkt.ip.IP_PROTO_IGMP:
                c = '{:>8}  {:<15}: {:<6} -->  {:<15}: {:<6}'.format(counter,
                                                                     ipDecode(ip.src),
                                                                     ip.data.sport,
                                                                     ipDecode(ip.dst),
                                                                     ip.data.dport)

            with open(tempFile,'a') as f:
                if c is not '':
                    c += '\n'
                    f.writelines(c)

        os.system("less {}".format(tempFile))
        os.system('rm {}'.format(tempFile))


    def printTotals(self):
        # Print packet totals
        print("|{:-<30}|".format(''))
        print self.timeStart
        print self.timeEnd

        print self.timeEnd - self.timeStart

        print("| Ethernet     {:>5}  {:>6.2f}%  |".format(self.counter, self.getPercentage(self.counter)))
        print("|   NON-IP     {:>5}  {:>6.2f}%  |".format(self.nonipcounter, self.getPercentage(self.nonipcounter)))
        print("|     ARP      {:>5}  {:>6.2f}%  |".format(self.arpcounter, self.getPercentage(self.arpcounter)))
        print("|   IP         {:>5}  {:>6.2f}%  |".format(self.ipcounter, self.getPercentage(self.ipcounter)))
        print("|     TCP      {:>5}  {:>6.2f}%  |".format(self.tcpcounter, self.getPercentage(self.smtpcounter)))
        print("|       HTTP   {:>5}  {:>6.2f}%  |".format(self.httpcounter, self.getPercentage(self.httpcounter)))
        print("|       HTTPS  {:>5}  {:>6.2f}%  |".format(self.httpscounter, self.getPercentage(self.httpscounter)))
        print("|       SMTP   {:>5}  {:>6.2f}%  |".format(self.smtpcounter, self.getPercentage(self.smtpcounter)))
        print("|       FTP    {:>5}  {:>6.2f}%  |".format(self.ftpcounter, self.getPercentage(self.ftpcounter)))
        print("|       SSH    {:>5}  {:>6.2f}%  |".format(self.sshcounter, self.getPercentage(self.sshcounter)))
        print("|       NTP    {:>5}  {:>6.2f}%  |".format(self.ntpcounter, self.getPercentage(self.ntpcounter)))
        print("|       ICMP   {:>5}  {:>6.2f}%  |".format(self.icmpcounter, self.getPercentage(self.icmpcounter)))
        print("|       IPV6   {:>5}  {:>6.2f}%  |".format(self.ipv6counter, self.getPercentage(self.ipv6counter)))
        print("|       telnet {:>5}  {:>6.2f}%  |".format(self.telnetcounter, self.getPercentage(self.telnetcounter)))
        print("|       whois  {:>5}  {:>6.2f}%  |".format(self.whoiscounter, self.getPercentage(self.whoiscounter)))
        print("|       rsync  {:>5}  {:>6.2f}%  |".format(self.rsynccounter, self.getPercentage(self.rsynccounter)))
        print("|     UDP      {:>5}  {:>6.2f}%  |".format(self.udpcounter, self.getPercentage(self.udpcounter)))
        print("|       DHCP   {:>5}  {:>6.2f}%  |".format(self.dhcpcounter, self.getPercentage(self.dhcpcounter)))
        print("|{:-<30}|".format(''))
        self.other = self.counter-(self.arpcounter+ \
                                   self.httpcounter+ \
                                   self.httpscounter+ \
                                   self.smtpcounter+ \
                                   self.ftpcounter+ \
                                   self.sshcounter+ \
                                   self.dhcpcounter+ \
                                   self.ntpcounter+ \
                                   self.icmpcounter +\
                                   self.ipv6counter+ \
                                   self.telnetcounter+ \
                                   self.whoiscounter+ \
                                   self.rsynccounter)


    def printPacketPercentage(self):
        # Print packet percentage

        print("ARP     {:>5.0f}  {:>6.2f}%".format(self.arpcounter, self.getPercentage(self.arpcounter)))
        print("HTTP    {:>5.0f}  {:>6.2f}%".format(self.httpcounter, self.getPercentage(self.httpcounter)))
        print("HTTPS   {:>5.0f}  {:>6.2f}%".format(self.httpscounter, self.getPercentage(self.httpscounter)))
        print("SMTP    {:>5.0f}  {:>6.2f}%".format(self.smtpcounter, self.getPercentage(self.smtpcounter)))
        print("FTP     {:>5.0f}  {:>6.2f}%".format(self.ftpcounter, self.getPercentage(self.ftpcounter)))
        print("SSH     {:>5.0f}  {:>6.2f}%".format(self.sshcounter, self.getPercentage(self.sshcounter)))
        print("DHCP    {:>5.0f}  {:>6.2f}%".format(self.dhcpcounter, self.getPercentage(self.dhcpcounter)))
        print("NTP     {:>5.0f}  {:>6.2f}%".format(self.ntpcounter, self.getPercentage(self.ntpcounter)))
        print("IPV6    {:>5.0f}  {:>6.2f}%".format(self.ipv6counter, self.getPercentage(self.ipv6counter)))
        print("telnet  {:>5.0f}  {:>6.2f}%".format(self.telnetcounter, self.getPercentage(self.telnetcounter)))
        print("whois   {:>5.0f}  {:>6.2f}%".format(self.whoiscounter, self.getPercentage(self.whoiscounter)))
        print("rsync   {:>5.0f}  {:>6.2f}%".format(self.rsynccounter, self.getPercentage(self.rsynccounter)))
        print("other   {:>5.0f}  {:>6.2f}%".format(self.other, self.getPercentage(self.other)))
        print("total   {:>5.0f}  {:>6.2f}%".format(self.counter, self.getPercentage(self.counter)))
        print("--------------------------------------------------------------")


    def printSubnets(self):
        # Print addresses
        print ("Address \t \t Occurences")
        for key, value in sorted(self.subnets.iteritems(), key=lambda t: int(t[0].split(".")[0])):
            print ("%s/16 \t = \t %s" %(key, value))


    def getPercentage(self, number):
        return ((number/float(self.counter))*100)



def ipDecode(p):
    return ".".join(["{}".format(ord(x)) for x in str(p)])




if __name__ =="__main__":

    test = scan(sys.argv[1])

    test.printTotals()
    test.printPacketPercentage()

    test.http.printHttpRequests(vv=True)

    test.printConnections()
