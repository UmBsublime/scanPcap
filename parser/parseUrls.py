import dpkt

from parser.protoParser import ProtoParser


class ParseUrls(ProtoParser):

    def __init__(self, tcpList):
        self.tcpList = tcpList
        ProtoParser.__init__(self, '.urls.tmp')

    def prepOut(self, v=False):

        for tcp in self.tcpList:

            try:
                p = tcp.dport
            except AttributeError:
                continue

            if p == 80 and len(tcp.data) > 0:

                try:
                    http = dpkt.http.Request(tcp.data)
                    host = http.headers['host']

                except dpkt.dpkt.UnpackError as e:         # ABSOLUTELY need to fix this
                    #print ("[Known Bug] I/O error({}): ".format(e))
                    continue
                    #print(len(tcp.data))
                    #print(tcp.data)

                u = ''
                if host.startswith('www'):
                    if v:
                        #HEADERS
                        u += '\n{:-<18}|\n'.format('HEADERS')
                        for key, value in http.headers.items():
                            u += '{:<18}: {}\n'.format(key, value)
                    #URL
                    u += '{:<18}: {}\n'.format('URL',host, http.uri)



                with open(self.tempFile,'a') as f:
                    f.writelines(u)

        self.tcpList = None
        self.preped = True