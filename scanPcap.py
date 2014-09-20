#!/usr/bin/env python

import os
import analyze
import thread

from optparse import OptionParser

import parser.parseHttp as http
import parser.parseDns as dns
import parser.parseArp as arp
import parser.parseUrls as urls

version = '0.0.3'

def setArgs():
    global options
    parser = OptionParser(usage = 'usage: %prog [-r FILE] arguments')
    parser.add_option("-r", "--read", dest="filename",
                      help="read pcap FILE", metavar="FILE")
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose", default=False,
                      help="prints verbose output for any following argument")
    parser.add_option("-u", "--url",
                      action="store_true", dest="pUrl", default=False,
                      help="shows url requests")
    parser.add_option("-c", "--conn",
                      action="store_true", dest="pConn", default=False,
                      help="shows ip connections")
    parser.add_option("-t", "--http",
                      action="store_true", dest="pHttp", default=False,
                      help="shows http requests")
    parser.add_option("-s", "--stats",
                      action="store_true", dest="pStats", default=False,
                      help="print statistics")
    parser.add_option("-d", "--dns",
                      action="store_true", dest="pDns", default=False,
                      help="print dns requests/responses")
    parser.add_option("-a", "--arp",
                      action="store_true", dest="pArp", default=False,
                      help="print arp requests/responses")
    parser.add_option("-n", "--subnet",
                      action="store_true", dest="pSubnet", default=False,
                      help="print stats about different subnets")

    (options, args) = parser.parse_args()
    #print("\nDEBUG: {}\n".format(str(options)))

    if options.filename is None:
        parser.error('Filename not given')
        #(options, args) = parser.parse_args(["-h"])

    return options

def console(args, c):

    #if True in args.values():
    #    return True
    commandLine = False

    if args.pUrl:
        u = urls.ParseUrls(c.tcpPacketList)
        u.out(rmTemp=True)
        commandLine = True

    if args.pHttp:
        h = http.ParseHttp(c.tcpPacketList, v=True, vv=args.verbose)
        h.out(rmTemp=True)
        commandLine = True

    if args.pDns:
        d = dns.ParseDns(c.ethPacketList)
        d.out(rmTemp=True)
        commandLine = True

    if args.pArp:
        a = arp.ParseArp(c.arpPacketList, v=args.verbose)
        a.out(rmTemp=True)
        commandLine = True

    if args.pSubnet:
        c.printSubnets(24)
        commandLine = True

    if args.pStats:
        c.printTotals()
        commandLine = True

    if args.pConn:
        c.printConnections(v=args.verbose)
        commandLine = True

    return commandLine

def interactive(capture):

    menu = [['1', 'Print Subnets'],
            ['2', 'Print Connections'],
            ['3', 'Print HTTP Requests'],
            ['4', 'Print DNS'],
            ['5', 'Print URLS'],
            ['6', 'Print ARP'],
            ['^C', 'Exit']]

    u = urls.ParseUrls(capture.tcpPacketList)
    h = http.ParseHttp(capture.tcpPacketList, vv=True)
    d = dns.ParseDns(capture.ethPacketList)
    a = arp.ParseArp(capture.arpPacketList, v=True)

    thread.start_new_thread(h.prepOut, ())
    thread.start_new_thread(u.prepOut, ())
    thread.start_new_thread(a.prepOut, ())
    thread.start_new_thread(d.prepOut, ())

    os.system('clear')

    try:
        while True:
            os.system('clear')
            print('|{:-<40}|'.format(''))
            print('|{:<40}|'.format(__file__.split('/')[-1] + ' v.' + version))
            capture.printTotals()
            for e in menu:
                print('{}. {}'.format(e[0], e[1]))

            choice = input('\nChoice: ')

            # Make everything verbose when running interactively
            if choice is 1:
                capture.printSubnets(24)
                raw_input('Press any key to continue')
            elif choice is 2:
                capture.printConnections(v=True)
            elif choice is 3:
                h.out()
            elif choice is 4:
                d.out()
            elif choice is 5:
                u.out()
            elif choice is 6:
                a.out()

    except KeyboardInterrupt:
        print
        exit()

    finally:
        # Clean up
        h.cleanUp()
        d.cleanUp()
        u.cleanUp()
        a.cleanUp()



def main():

    print('\n--> ANALYZING CAPTURE . . .\n')

    args = setArgs()
    capture = analyze.scan(options.filename)



    if not console(args, capture):
        interactive(capture)




if __name__ == '__main__':
    main()
