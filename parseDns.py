import dpkt

from helper import ipDecode
from protoParser import ProtoParser

class ParseDns(ProtoParser):

    def __init__(self, ethList):
        self.ethList = ethList
        ProtoParser.__init__(self, '.dns.tmp')

    def prepOut(self):

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

            c = self.formatDns(dns)

            with open(self.tempFile,'a') as f:
                f.writelines(c)

    def formatDns(self, dns):

        c =''
        if dns.qr == dpkt.dns.DNS_Q:
            #query
            try:
                c += '|{:->12}|\n'.format('')
                c += '| Query      {}|\n'.format('')
                c += '|{:->50}|\n'.format('')
                for qname in dns.qd:
                    c += '| Name:        {:<36}|\n'.format(qname.name)
            except:
                pass
                #continue
        elif dns.qr == dpkt.dns.DNS_R:
            #reply
            try:
                c += '|{:->12}|\n'.format('')
                c += '| Response   {}|\n'.format('')
                c += '|{:->50}|\n'.format('')
                for answer in dns.an:
                    if answer.type == 1:  # DNS_A
                        if answer.name not in c:
                            c += "| A RECORD     {:<36}|\n".format('')
                            c += "| Domain Name: {:<36}|\n".format(answer.name)
                        c += "| IP Address:  {:<36}|\n".format(ipDecode(answer.rdata))
            except:
                pass

        # remove empty responses
        if '---|' in c[-10:]:
            return ''
        c += '|{:->50}|\n\n'.format('')

        return c
