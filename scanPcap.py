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

def console(capture, args):
    commandLine = False
    if args.pUrl:
        capture.urls.prepOut()
        capture.urls.out()
        capture.urls.cleanUp()
        commandLine = True

    if args.pHttp:
        if args.verbose:
            capture.http.prepOut(vv=True)
            capture.http.out()
        else:
            capture.http.prepOut(v=True)
            capture.http.out()
        capture.http.cleanUp()
        commandLine = True

    if args.pDns:
        capture.dns.prepOut()
        capture.dns.out()
        capture.dns.cleanUp()
        commandLine = True

    if args.pStats:
        capture.printTotals()
        commandLine = True

    if args.pConn:
        if args.verbose:
            capture.printConnections(v=True)
        else:
            capture.printConnections()
        commandLine = True

    if args.pArp:
        if args.verbose:
            capture.arp.prepOut(True)
            capture.arp.out()
        else:
            capture.arp.prepOut()
            capture.arp.out()
        capture.arp.cleanUp()
        commandLine = True

    if args.pSubnet:
        capture.printSubnets(24)
        commandLine = True


    return commandLine

def interactive(capture):

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
            print('1. Print URLS')
            print('2. Print HTTP Requests')
            print('3. Print Connections')
            print('4. Subnets')
            print('5. DNS')
            print('6. ARP')
            print('^C Quit')

            choice = input('\nChoice: ')

            # Make everything verbose when running interactively
            if choice is 1:
                capture.urls.out()
            elif choice is 2:
                #http.join()
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
