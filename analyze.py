#!/usr/bin/env python

import dpkt
import socket
import sys
import os

from commands import getoutput

import analyzeHttp as http
import analyzeDns as dns
import analyzeArp as arp



class scan():

    def __init__(self, filename):

        self.filename = filename

        self.startTime = None
        self.endTime = None
        self.timeDelta = None

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
        self.startTime = getoutput("tcpdump -nttttr {} | head -n 1 | cut -d' ' -f1-2". format(self.filename))
        self.startTime = self.startTime.split('\n')
        #print ('Start Time: {}'.format(self.startTime[1]))

        self.endTime = getoutput("tcpdump -nttttr {} | tail -n 1 | cut -d' ' -f1-2". format(self.filename))
        self.endTime = self.endTime.split('\n')
        #print ('End Time: {}'.format(self.endTime[1]))

        tS = datetime_from_str(self.startTime[1])
        tE =  datetime_from_str(self.endTime[1])
        self.timeDelta  = tE[1] - tS[1]

        for ts,pkt in capture:
            self.counter+=1

            try:
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
                    address = '.'.join(string.split("."))#[:2]) # ---->>>> Can easily change subnet statistic here
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
            except AttributeError:
                continue

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

        print ('File Name:  {}'.format(self.filename))
        print ('Start Time: {}'.format(self.startTime[1]))
        print ('End Time:   {}'.format(self.endTime[1]))
        print ('Duration:   {}'.format(self.timeDelta))
        print("|{:-<33}|".format(''))
        print("| Ethernet     {:>8}  {:>6.2f}%  |".format(self.counter, self.getPercentage(self.counter)))
        print("|   NON-IP     {:>8}  {:>6.2f}%  |".format(self.nonipcounter, self.getPercentage(self.nonipcounter)))
        print("|     ARP      {:>8}  {:>6.2f}%  |".format(self.arpcounter, self.getPercentage(self.arpcounter)))
        print("|   IP         {:>8}  {:>6.2f}%  |".format(self.ipcounter, self.getPercentage(self.ipcounter)))
        print("|     TCP      {:>8}  {:>6.2f}%  |".format(self.tcpcounter, self.getPercentage(self.smtpcounter)))
        print("|       HTTP   {:>8}  {:>6.2f}%  |".format(self.httpcounter, self.getPercentage(self.httpcounter)))
        print("|       HTTPS  {:>8}  {:>6.2f}%  |".format(self.httpscounter, self.getPercentage(self.httpscounter)))
        print("|       SMTP   {:>8}  {:>6.2f}%  |".format(self.smtpcounter, self.getPercentage(self.smtpcounter)))
        print("|       FTP    {:>8}  {:>6.2f}%  |".format(self.ftpcounter, self.getPercentage(self.ftpcounter)))
        print("|       SSH    {:>8}  {:>6.2f}%  |".format(self.sshcounter, self.getPercentage(self.sshcounter)))
        print("|       NTP    {:>8}  {:>6.2f}%  |".format(self.ntpcounter, self.getPercentage(self.ntpcounter)))
        print("|       ICMP   {:>8}  {:>6.2f}%  |".format(self.icmpcounter, self.getPercentage(self.icmpcounter)))
        print("|       IPV6   {:>8}  {:>6.2f}%  |".format(self.ipv6counter, self.getPercentage(self.ipv6counter)))
        print("|       telnet {:>8}  {:>6.2f}%  |".format(self.telnetcounter, self.getPercentage(self.telnetcounter)))
        print("|       whois  {:>8}  {:>6.2f}%  |".format(self.whoiscounter, self.getPercentage(self.whoiscounter)))
        print("|       rsync  {:>8}  {:>6.2f}%  |".format(self.rsynccounter, self.getPercentage(self.rsynccounter)))
        print("|     UDP      {:>8}  {:>6.2f}%  |".format(self.udpcounter, self.getPercentage(self.udpcounter)))
        print("|       DHCP   {:>8}  {:>6.2f}%  |".format(self.dhcpcounter, self.getPercentage(self.dhcpcounter)))
        print("|{:-<33}|".format(''))
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


    def printSubnets(self, subMask):
        # Print addresses

        import string
        address = '.'.join(string.split("."))#[:2])




        print ("Address lol\t \t Occurences")
        for key, value in sorted(self.subnets.iteritems(), key=lambda t: int(t[0].split(".")[0])):
        #for key, value in self.subnets.items():
            #key=lambda t: int(t[0].split(".")[0])):

            if subMask is 24:
                address = '.'.join(key.split(".")[:3])
            elif subMask is 16:
                address = '.'.join(key.split(".")[:2])
            elif subMask is 16:
                address = '.'.join(key.split(".")[:1])
            else:
                address = key
            print ("  {:<20}/{:<5}=   {}".format(address, subMask, value))


    def getPercentage(self, number):
        return ((number/float(self.counter))*100)



def ipDecode(p):
    return ".".join(["{}".format(ord(x)) for x in str(p)])





def datetime_from_str(time_str):

    # got from http://code.activestate.com/recipes/577135-parse-a-datetime-string-to-a-datetime-instance/
    """Return (<scope>, <datetime.datetime() instance>) for the given
    datetime string.

    >>> _datetime_from_str("2009")
    ('year', datetime.datetime(2009, 1, 1, 0, 0))
    >>> _datetime_from_str("2009-12")
    ('month', datetime.datetime(2009, 12, 1, 0, 0))
    >>> _datetime_from_str("2009-12-25")
    ('day', datetime.datetime(2009, 12, 25, 0, 0))
    >>> _datetime_from_str("2009-12-25 13")
    ('hour', datetime.datetime(2009, 12, 25, 13, 0))
    >>> _datetime_from_str("2009-12-25 13:05")
    ('minute', datetime.datetime(2009, 12, 25, 13, 5))
    >>> _datetime_from_str("2009-12-25 13:05:14")
    ('second', datetime.datetime(2009, 12, 25, 13, 5, 14))
    >>> _datetime_from_str("2009-12-25 13:05:14.453728")
    ('microsecond', datetime.datetime(2009, 12, 25, 13, 5, 14, 453728))
    """
    import time
    import datetime
    formats = [
        # <scope>, <pattern>, <format>
        ("year", "YYYY", "%Y"),
        ("month", "YYYY-MM", "%Y-%m"),
        ("day", "YYYY-MM-DD", "%Y-%m-%d"),
        ("hour", "YYYY-MM-DD HH", "%Y-%m-%d %H"),
        ("minute", "YYYY-MM-DD HH:MM", "%Y-%m-%d %H:%M"),
        ("second", "YYYY-MM-DD HH:MM:SS", "%Y-%m-%d %H:%M:%S"),
        # ".<microsecond>" at end is manually handled below
        ("microsecond", "YYYY-MM-DD HH:MM:SS", "%Y-%m-%d %H:%M:%S"),
    ]
    for scope, pattern, format in formats:
        if scope == "microsecond":
            # Special handling for microsecond part. AFAIK there isn't a
            # strftime code for this.
            if time_str.count('.') != 1:
                continue
            time_str, microseconds_str = time_str.split('.')
            try:
                microsecond = int((microseconds_str + '000000')[:6])
            except ValueError:
                continue
        try:
            # This comment here is the modern way. The subsequent two
            # lines are for Python 2.4 support.
            #t = datetime.datetime.strptime(time_str, format)
            t_tuple = time.strptime(time_str, format)
            t = datetime.datetime(*t_tuple[:6])
        except ValueError:
            pass
        else:
            if scope == "microsecond":
                t = t.replace(microsecond=microsecond)
            return scope, t
    else:
        raise ValueError("could not determine date from %r: does not "
            "match any of the accepted patterns ('%s')"
            % (time_str, "', '".join(s for s,p,f in formats)))





if __name__ =="__main__":

    test = scan(sys.argv[1])

    test.printTotals()
    test.printPacketPercentage()

    test.http.printHttpRequests(vv=True)

    test.printConnections()



