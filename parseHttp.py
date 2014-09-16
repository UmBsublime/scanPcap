import dpkt

from protoParser import ProtoParser

class ParseHttp(ProtoParser):

    def __init__(self, tcpList):
        self.tcpList = tcpList
        ProtoParser.__init__(self, '.http.tmp')

    def prepOut(self, v=False, vv=False):
        if vv:
            v = True
        for tcp in self.tcpList:
            r = ''
            try:
                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:

                        http = dpkt.http.Request(tcp.data)
                        r += '\n{:-<18}|\n{:<18}:\n'.format('','HTTP REQUEST')
                        if v:
                            r += '{:<18}: {}\n'.format('PACKET LENGTH', len(tcp.data))
                            if vv:
                                r +='{:<18}: {}\n'.format('VERSION', http.version)
                                r += '{:<18}: {}\n'.format('METHOD',http.method)
                                r += '{:-<18}|\n'.format('HEADERS')
                                for key, value in http.headers.items():
                                    r += '{:<18}: {}\n'.format(key, value)
                            else:
                                r += '{:-<18}|\n'.format('HEADERS')
                                for key, value in http.headers.items():
                                    if  'host' in key:
                                        r += '{:<18}: {}\n'.format(key, value)
                                    if 'referer' in key:
                                        r += '{:<18}: {}\n'.format(key, value)
                                    if 'user-agent' in key:
                                        r += '{:<18}: {}\n'.format(key, value)
                                    if 'connection' in key:
                                        r += '{:<18}: {}\n'.format(key, value)

                        host = http.headers['host']
                        if host.startswith('www'):
                            r += '{:<18}: {}\n'.format('URL',host, http.uri)
                        r += '{:-<18}|\n'.format('')
                    except dpkt.dpkt.UnpackError.InvalidHeader as e:
                        print ("I/O error({}): ".format(e))
                        print(len(tcp.data))
                        print(tcp.data)
                        pass
            except AttributeError:
                pass

            with open(self.tempFile,'a') as f:
                f.writelines(r)
