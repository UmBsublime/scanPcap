import dpkt
import socket

class analyzeDns():

    def __init__(self, ethList):

        self.ethList = ethList
        pass


    def analyze(self):

        for eth in self.ethList:

            if eth.type != 2048:
                continue

            try:
                ip = eth.data
            except:
                continue
            if ip.p != 17:
                continue

            try:
                udp = ip.data
            except:
                continue

            if udp.sport != 53 and udp.dport != 53:
                continue

            try:
                dns = dpkt.dns.DNS(udp.data)
            except:
                continue



            if dns.qr == dpkt.dns.DNS_Q:

                #query
                try:
                    print('Q')
                    for qname in dns.qd:
                        print(qname.name)
                except:
                    continue

            elif dns.qr == dpkt.dns.DNS_R:
                #reply

                try:
                    print('R')
                    for answer in dns.an:
                        if answer.type == 1:  # DNS_A
                            print("A RECORD")
                            print("Domain Name: {}\nIP Address: {}".format(answer.name, socket.inet_ntoa(answer.rdata)))
                except:
                    continue




