from helper import ipDecode, addColonsToMac, convertMacToStr
from protoParser import ProtoParser

class ParseArp(ProtoParser):

    def __init__(self, arpList):
        self.arpList = arpList
        ProtoParser.__init__(self, '.arp.tmp')

    def prepOut(self, v=False):
        for arp in self.arpList:
            a= ''

            if arp.op == 1:
                if v:
                    a += '{:^42}\n'.format('Request')
                    a += '{:-<42}\n'.format('')
                a += ' {:^17}who-has{:^17}\n'.format(ipDecode(arp.spa), ipDecode(arp.tpa))
                if v:
                    a += ' {}  -->  {:^17}\n'.format(addColonsToMac(convertMacToStr(arp.sha)), 'BROADCAST')
            elif arp.op == 2:
                if v:
                    a += '{:^42}\n'.format('Reply')
                    a += '{:-<42}\n'.format('')
                a += ' {:^17} gives {:^17}\n'.format(ipDecode(arp.spa), ipDecode(arp.tpa))
                a += ' {}  -->  {}\n'.format(addColonsToMac(convertMacToStr(arp.sha)),
                                             addColonsToMac(convertMacToStr(arp.tha)))

            a += '{:-<42}\n'.format('')

            with open(self.tempFile,'a') as f:
                f.writelines(a)

