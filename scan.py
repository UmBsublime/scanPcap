#!/usr/bin/env python

import dpkt
import socket
import sys
import os

import analyzeHttp as http
import analyzeDns as dns

from math import trunc

class scan():

    def __init__(self, filename):

        self.filename = filename

        self.counter=0.0
        self.ipcounter=0.0
        self.nonipcounter=0.0
        self.tcpcounter=0.0
        self.udpcounter=0.0
        self.arpcounter=0.0
        self.httpcounter=0.0
        self.httpscounter=0.0
        self.smtpcounter=0.0
        self.dhcpcounter=0.0
        self.ftpcounter=0.0
        self.sshcounter=0.0
        self.ntpcounter=0.0
        self.telnetcounter=0.0
        self.whoiscounter=0.0
        self.rsynccounter=0.0
        self.icmpcounter=0.0
        self.ipv6counter=0.0


        self.ethPacketList = []
        self.ipPacketList = []
        self.tcpPacketList = []
        self.udpPacketList = []

        # Subnet Dictionary
        self.subnets = {}


        # initialize counters
        self.setCounters()

        # plug-in httpAnalyze
        self.http = http.analyzeHttp(self.tcpPacketList)
        self.dns = dns.analyzeDns(self.ethPacketList)


    def setCounters(self):
        # Packet processing loop
        for ts,pkt in dpkt.pcap.Reader(open(self.filename,'rb')):
            self.counter+=1

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
        counter = 0
        connections = ""
        for ip in self.ipPacketList:
            try:
                if ip.p != dpkt.ip.IP_PROTO_ICMP: # and ip.p != dpkt.ip.PROTO_IGMP:
                    counter += 1
                    #if v:
                        #print(counter),
                    #print('{:<15}: {:<6} -->  {:<15}: {:<6}'.format(ip_decode(ip.src),
                    #                                         ip.data.sport,
                    #                                         ip_decode(ip.dst),
                    #:                                         ip.data.dport))

                    test = '{:<15}: {:<6} -->  {:<15}: {:<6}'.format(ipDecode(ip.src),
                                                             ip.data.sport,
                                                             ipDecode(ip.dst),
                                                             ip.data.dport)
                    connections += (test + "\n")
            except AttributeError:
                print('banana')

        os.system("echo '{}' | less".format(connections))

    def printTotals(self):
        # Print packet totals
        print("|{:-<37}|".format(''))
        #print ("Total number of ETHERNET packets : {}".format(self.counter))
        #print ("  Total number of IP packets : {}".format(self.ipcounter))
        #print ("    Total number of TCP packets : {}".format(self.tcpcounter))
        print "| Ethernet             {:>5.0f}  {:>6.2f}% |".format(self.counter, getPercentage(self.counter, self.counter))
        print "|     IP               {:>5.0f}  {:>6.2f}% |".format(self.ipcounter, getPercentage(self.ipcounter, self.counter))
        print "|         TCP          {:>5.0f}  {:>6.2f}% |".format(self.tcpcounter, getPercentage(self.smtpcounter, self.counter))

        print "|             HTTP     {:>5.0f}  {:>6.2f}% |".format(self.httpcounter, getPercentage(self.httpcounter, self.counter))
        print "|             HTTPS    {:>5.0f}  {:>6.2f}% |".format(self.httpscounter, getPercentage(self.httpscounter, self.counter))
        print "|             SMTP     {:>5.0f}  {:>6.2f}% |".format(self.smtpcounter, getPercentage(self.smtpcounter, self.counter))
        print "|             FTP      {:>5.0f}  {:>6.2f}% |".format(self.ftpcounter, getPercentage(self.ftpcounter, self.counter))
        print "|             SSH      {:>5.0f}  {:>6.2f}% |".format(self.sshcounter, getPercentage(self.sshcounter, self.counter))
        print "|             NTP      {:>5.0f}  {:>6.2f}% |".format(self.ntpcounter, getPercentage(self.ntpcounter, self.counter))
        print "|             ICMP     {:>5.0f}  {:>6.2f}% |".format(self.icmpcounter, getPercentage(self.icmpcounter, self.counter))
        print "|             IPV6     {:>5.0f}  {:>6.2f}% |".format(self.ipv6counter, getPercentage(self.ipv6counter, self.counter))
        print "|             telnet   {:>5.0f}  {:>6.2f}% |".format(self.telnetcounter, getPercentage(self.telnetcounter, self.counter))
        print "|             whois    {:>5.0f}  {:>6.2f}% |".format(self.whoiscounter, getPercentage(self.whoiscounter, self.counter))
        print "|             rsync    {:>5.0f}  {:>6.2f}% |".format(self.rsynccounter, getPercentage(self.rsynccounter, self.counter))
        print "|         UDP          {:>5.0f}  {:>6.2f}% |".format(self.udpcounter, getPercentage(self.udpcounter, self.counter))
        #print ("      Total number of DHCP packets : {}".format(self.dhcpcounter))
        print "|             DHCP     {:>5.0f}  {:>6.2f}% |".format(self.dhcpcounter, getPercentage(self.dhcpcounter, self.counter))
        print "|     NON-IP           {:>5.0f}  {:>6.2f}% |".format(self.nonipcounter, getPercentage(self.nonipcounter, self.counter))
        print "|         ARP          {:>5.0f}  {:>6.2f}% |".format(self.arpcounter, getPercentage(self.arpcounter, self.counter))
        #print ("  Total number of NON-IP packets : {}".format(self.nonipcounter))
        #print ("    Total number of ARP packets : {}".format(self.arpcounter))
        print("|{:-<37}|".format(''))
        #print ("--------------------------------------------------------------")
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
    #66102
    def printPacketPercentage(self):
        # Print packet percentage
        print "ARP     {:>5.0f}  {:>6.2f}%".format(self.arpcounter, getPercentage(self.arpcounter, self.counter))
        print "HTTP    {:>5.0f}  {:>6.2f}%".format(self.httpcounter, getPercentage(self.httpcounter, self.counter))
        print "HTTPS   {:>5.0f}  {:>6.2f}%".format(self.httpscounter, getPercentage(self.httpscounter, self.counter))
        print "SMTP    {:>5.0f}  {:>6.2f}%".format(self.smtpcounter, getPercentage(self.smtpcounter, self.counter))
        print "FTP     {:>5.0f}  {:>6.2f}%".format(self.ftpcounter, getPercentage(self.ftpcounter, self.counter))
        print "SSH     {:>5.0f}  {:>6.2f}%".format(self.sshcounter, getPercentage(self.sshcounter, self.counter))
        print "DHCP    {:>5.0f}  {:>6.2f}%".format(self.dhcpcounter, getPercentage(self.dhcpcounter, self.counter))
        print "NTP     {:>5.0f}  {:>6.2f}%".format(self.ntpcounter, getPercentage(self.ntpcounter, self.counter))
        print "IPV6    {:>5.0f}  {:>6.2f}%".format(self.ipv6counter, getPercentage(self.ipv6counter, self.counter))
        print "telnet  {:>5.0f}  {:>6.2f}%".format(self.telnetcounter, getPercentage(self.telnetcounter, self.counter))
        print "whois   {:>5.0f}  {:>6.2f}%".format(self.whoiscounter, getPercentage(self.whoiscounter, self.counter))
        print "rsync   {:>5.0f}  {:>6.2f}%".format(self.rsynccounter, getPercentage(self.rsynccounter, self.counter))
        print "other   {:>5.0f}  {:>6.2f}%".format(self.other, getPercentage(self.other, self.counter))
        print "total   {:>5.0f}  {:>6.2f}%".format(self.counter, getPercentage(self.counter, self.counter))
        print "--------------------------------------------------------------"

    def printSubnets(self):
        # Print addresses
        print "Address \t \t Occurences"
        for key, value in sorted(self.subnets.iteritems(), key=lambda t: int(t[0].split(".")[0])):
            print "%s/16 \t = \t %s" %(key, value)



def getPercentage(number, total):
    return ((number/total)*100)


def ipDecode(p):
    return ".".join(["{}".format(ord(x)) for x in str(p)])


def addColonsToMac(macAddr):
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12 / 2): 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(macAddr[i*2:i*2+2])
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r


if __name__ =="__main__":

    test = scan(sys.argv[1])

    test.printTotals()
    test.printPacketPercentage()

    test.http.printHttpRequests(vv=True)

    test.printConnections()