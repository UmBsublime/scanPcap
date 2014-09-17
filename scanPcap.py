#!/usr/bin/env python

import os
import analyze
import thread

from optparse import OptionParser


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

def console(c, args):

    commandLine = False

    if args.pUrl:
        c.urls.prepOut()
        c.urls.out()
        c.urls.cleanUp()
        commandLine = True

    if args.pHttp:
        c.http.prepOut(v=True, vv=args.verbose)
        c.http.out()
        c.http.cleanUp()
        commandLine = True

    if args.pDns:
        c.dns.prepOut()
        c.dns.out()
        c.dns.cleanUp()
        commandLine = True

    if args.pArp:
        c.arp.prepOut(v=args.verbose)
        c.arp.out()
        c.arp.cleanUp()
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

    thread.start_new_thread(capture.http.prepOut,(True, True))
    thread.start_new_thread(capture.arp.prepOut, (True,))
    thread.start_new_thread(capture.dns.prepOut, ())
    thread.start_new_thread(capture.urls.prepOut, ())

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
                capture.urls.out()
            elif choice is 2:
                capture.http.out()
            elif choice is 3:
                capture.printConnections(v=True)
            elif choice is 4:
                capture.printSubnets(24)
                raw_input('Press any key to continue')
            elif choice is 5:
                capture.dns.out()
            elif choice is 6:
                capture.arp.out()

    except KeyboardInterrupt:
        print
        exit()

    finally:
        # Clean up
        capture.http.cleanUp()
        capture.urls.cleanUp()
        capture.dns.cleanUp()
        capture.arp.cleanUp()



def main():

    print('\n--> ANALYZING CAPTURE . . .\n')

    args = setArgs()
    capture = analyze.scan(options.filename)

    if not console(capture, args):
        interactive(capture)




if __name__ == '__main__':
    main()
