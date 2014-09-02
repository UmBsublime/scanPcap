#!/usr/bin/env python

import os
import analyze


from optparse import OptionParser


#import scan

def setArgs():
    global options
    parser = OptionParser(usage = 'usage: %prog [-r FILE] arguments')
    parser.add_option("-r", "--read", dest="filename",
                      help="read pcap FILE", metavar="FILE")
    parser.add_option("-v", "--verbose",
<<<<<<< HEAD
                      action="store_false", dest="verbose", default=False,
                      help="don't print status messages to stdout")
=======
                      action="store_true", dest="verbose", default=False,
                      help="prints verbose output for any following argument")
>>>>>>> dd0be56180df27d298d623bf6117fa8f2ddbb0f6
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
    print("\nDEBUG: {}\n".format(str(options)))



    if options.filename is None:
        parser.error('Filename not given')
        #(options, args) = parser.parse_args(["-h"])

    return options




def main():

    args = setArgs()
    commandLine = False
    print('\n--> ANALYZING CAPTURE . . .\n')

    test = analyze.scan(options.filename)

    if args.pUrl:
        test.http.printUrls()
        commandLine = True
    if args.pHttp:
        test.http.printHttpRequests(vv=True)
        commandLine = True
    if args.pDns:
        test.dns.analyze()
        commandLine = True
    if args.pStats:
        test.printTotals()
        commandLine = True
    if args.pConn:
        test.printConnections(v=True)
        commandLine = True
    if args.pArp:
        test.arp.printArp()
        commandLine = True
    if args.pSubnet:
        test.printSubnets(24)
        commandLine = True

    if commandLine:
        return 0


    while True:
        #os.system('clear')
        print('|{:-<19}'.format(''))
        print('| {:<17}|'.format('scan.py'))
        print('| File: {:<.11s}|'.format(options.filename))
        print('|{:-<19}\n'.format(''))
        print('1. Basic analysis')
        print('2. Print URLS')
        print('3. Print HTTP Requests')
        print('4. Print Connections')
        print('5. Subnets')
        print('6. DNS')
        print('7 ARP')
        print('^C quit')

        choice = input('\nChoice: ')
        if choice is 'q' or choice is 'Q':
            break

        if choice is 1:
            test.printTotals()
            test.printPacketPercentage()
            raw_input('Press any key to continue')
        elif choice is 2:
            test.http.printUrls()
        elif choice is 3:
            test.http.printHttpRequests(vv=True)
        elif choice is 4:
            test.printConnections(v=True)
        elif choice is 5:
            test.printSubnets(24)
            raw_input('Press any key to continue')
        elif choice is 6:
            test.dns.analyze()
        elif choice is 7:
            test.arp.printArp()

if __name__ == '__main__':
    main()
