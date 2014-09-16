import dpkt

from protoParser import ProtoParser


class ParseUrls(ProtoParser):

    def __init__(self, tcpList):
        self.tcpList = tcpList
        ProtoParser.__init__(self, '.urls.tmp')

    def prepOut(self, v=False):

        for tcp in self.tcpList:
            u = ''
            try:
                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:
                        http = dpkt.http.Request(tcp.data)
                        host = http.headers['host']

                        if host.startswith('www'):
                            if v:
                                #HEADERS
                                u += '\n{:-<18}|\n'.format('HEADERS')
                                for key, value in http.headers.items():
                                    u += '{:<18}: {}\n'.format(key, value)
                            #URL
                            u += '{:<18}: {}\n'.format('URL',host, http.uri)

                    except dpkt.dpkt.UnpackError.InvalidHeader as e:
                        print ("I/O error({}): ".format(e))
                        print(len(tcp.data))
                        print(tcp.data)
                        pass
            except AttributeError:
                pass


            with open(self.tempFile,'a') as f:
                f.writelines(u)
