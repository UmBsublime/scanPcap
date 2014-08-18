import dpkt

class analyzeHttp():

    def __init__(self, tcpList):

        self.tcpList = tcpList


    def printUrls(self, v=False):

        for tcp in self.tcpList:
            try:
                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:
                        http = dpkt.http.Request(tcp.data)
                        host = http.headers['host']

                        if host.startswith('www'):
                            if v:
                                #HEADERS
                                print('{:-<18}|'.format('HEADERS'))
                                for key, value in http.headers.items():
                                    print ('{:<18}: {}'.format(key, value))
                            #URL
                            print('{:<18}: {}'.format('URL',host, http.uri))

                    except dpkt.dpkt.UnpackError.InvalidHeader as e:
                        print ("I/O error({}): ".format(e))
                        print(len(tcp.data))
                        print(tcp.data)
                        pass
            except AttributeError:
                pass

    #def printArp(v=False):


    def printHttpRequests(self, v=False, vv=False):
        if vv:
            v = True
        for tcp in self.tcpList:

            try:
                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:

                        http = dpkt.http.Request(tcp.data)
                        print('\n{:-<18}|\n{:<18}:'.format('','HTTP REQUEST'))
                        if v:
                            print('{:<18}: {}'.format('PACKET LENGTH', len(tcp.data)))
                            if vv:
                                print('{:<18}: {}'.format('VERSION', http.version))
                                print('{:<18}: {}'.format('METHOD',http.method))
                            print('{:-<18}|'.format('HEADERS'))
                            for key, value in http.headers.items():
                                print ('{:<18}: {}'.format(key, value))

                        host = http.headers['host']
                        if host.startswith('www'):
                            print('{:<18}: {}'.format('URL',host, http.uri))
                        print('{:-<18}|'.format(''))
                    except dpkt.dpkt.UnpackError.InvalidHeader as e:
                        print ("I/O error({}): ".format(e))
                        print(len(tcp.data))
                        print(tcp.data)
                        pass
            except AttributeError:

                pass
