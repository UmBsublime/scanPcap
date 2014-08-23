import dpkt
import os

class analyzeHttp():

    def __init__(self, tcpList):

        self.tcpList = tcpList


    def printUrls(self, v=False):
        fileName = '.urls.tmp'
        u = ''
        for tcp in self.tcpList:
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


            with open(fileName,'a') as f:
                f.writelines(u)

        os.system("less {}".format(fileName))
        os.system("rm {}".format(fileName))
    #def printArp(v=False):


    def printHttpRequests(self, v=False, vv=False):
        fileName = '.requests.tmp'
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

            with open(fileName,'a') as f:
                f.writelines(r)

        os.system("less {}".format(fileName))
        os.system("rm {}".format(fileName))
