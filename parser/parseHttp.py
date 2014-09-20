import dpkt

from parser.protoParser import ProtoParser

class ParseHttp(ProtoParser):

    def __init__(self, tcpList, v=False, vv=False):
        self.tcpList = tcpList
        self.v = v
        self.vv =vv
        ProtoParser.__init__(self, '.http.tmp')

    def prepOut(self):
        if self.vv:
            self.v = True
        for tcp in self.tcpList:



            try:
                p = tcp.dport
            except AttributeError:
                continue

            if p == 80 and len(tcp.data) > 0:
                try:
                    http = dpkt.http.Request(tcp.data)
                except dpkt.dpkt.UnpackError as e:         # ABSOLUTELY need to fix this
                    #print ("[Known Bug] I/O error({}): ".format(e))
                    continue
                    #print(len(tcp.data))
                    #print(tcp.data)

                r = ''
                r += '\n{:-<18}|\n{:<18}:\n'.format('','HTTP REQUEST')
                if self.v:
                    r += '{:<18}: {}\n'.format('PACKET LENGTH', len(tcp.data))
                    if self.vv:
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


                with open(self.tempFile,'a') as f:
                    f.writelines(r)

        self.tcpList = None
        self.preped = True