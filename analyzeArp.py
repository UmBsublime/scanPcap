import dpkt

import os
import analyze
import struct

class analyzeArp():

    def __init__(self, arpList):

        self.arpList = arpList

        #self.analyze()
        pass

    def printArp(self):
        fileName = '.arp.tmp'
        for arp in self.arpList:
            a= ''
            if arp.op == 1:
                a += '{:^42}\n'.format('Request')
                a += '{:-<42}\n'.format('')
                a += ' {:^17}  asks {:^17}\n'.format(analyze.ipDecode(arp.spa),
                                           analyze.ipDecode(arp.tpa))
                a += ' {}  -->  {:^17}\n'.format(addColonsToMac(convertMacToStr(arp.sha)),
                                           'BROADCAST')
            elif arp.op == 2:
                #rtype = 'Reply'
                a += '{:^42}\n'.format('Reply')
                a += '{:-<42}\n'.format('')
                a += ' {:^17} gives {:^17}\n'.format(analyze.ipDecode(arp.spa),
                                           analyze.ipDecode(arp.tpa))
                a += ' {}  -->  {}\n'.format(addColonsToMac(convertMacToStr(arp.sha)),
                                           addColonsToMac(convertMacToStr(arp.tha)))

            a += '{:-<42}\n'.format('')

            with open(fileName,'a') as f:
                f.writelines(a)

        os.system("less {}".format(fileName))
        os.system("rm {}".format(fileName))





def convertMacToStr(buffer):
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr

def addColonsToMac(macAddr):
    """This function accepts a 12 hex digit string and converts it to a colon separated string"""
    s = list()
    for i in range(12 / 2): 	# mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(macAddr[i*2:i*2+2])
    r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
    return r
