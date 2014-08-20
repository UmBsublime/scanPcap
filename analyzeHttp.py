import dpkt
import os

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
        requests = ''
        for tcp in self.tcpList:
            request = ''
            try:
                if tcp.dport == 80 and len(tcp.data) > 0:
                    try:

                        http = dpkt.http.Request(tcp.data)
                        #print('\n{:-<18}|\n{:<18}:'.format('','HTTP REQUEST'))
                        request += '\n{:-<18}|\n{:<18}:\n'.format('','HTTP REQUEST')
                        if v:
                            #print('{:<18}: {}'.format('PACKET LENGTH', len(tcp.data)))
                            request += '{:<18}: {}\n'.format('PACKET LENGTH', len(tcp.data))
                            if vv:
                                #print('{:<18}: {}'.format('VERSION', http.version))
                                request +='{:<18}: {}\n'.format('VERSION', http.version)
                                #print('{:<18}: {}'.format('METHOD',http.method))
                                request += '{:<18}: {}\n'.format('METHOD',http.method)
                            #print('{:-<18}|'.format('HEADERS'))
                            request += '{:-<18}|\n'.format('HEADERS')
                            for key, value in http.headers.items():
                                #print('{:<18}: {}'.format(key, value))
                                request += '{:<18}: {}\n'.format(key, value)
                        host = http.headers['host']
                        if host.startswith('www'):
                            #print('{:<18}: {}'.format('URL',host, http.uri))
                            request += '{:<18}: {}\n'.format('URL',host, http.uri)
                        #print('{:-<18}|'.format(''))
                        request += '{:-<18}|\n'.format('')
                    except dpkt.dpkt.UnpackError.InvalidHeader as e:
                        print ("I/O error({}): ".format(e))
                        print(len(tcp.data))
                        print(tcp.data)
                        pass
            except AttributeError:

                pass

            requests += request

        os.system("echo '{}' | less".format(requests))
