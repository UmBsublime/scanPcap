#!/usr/bin/env python

import os
#import packetAnalize


from optparse import OptionParser


import scan

def setArgs():
    global options
    parser = OptionParser()
    parser.add_option("-r", "--read", dest="filename",
                      help="read pcap FILE", metavar="FILE")
    parser.add_option("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    (options, args) = parser.parse_args()
    print("\nDEBUG: {}\n".format(str(options)))

    print('\n--> ANALIZING CAPTURE . . .\n')

    if options.filename is None:
        (options, args) = parser.parse_args(["-h"]) 



def main():

    setArgs()

    test = scan.scan(options.filename)
    #testAnal.basicAnalysis()
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
            test.printSubnets()
            raw_input('Press any key to continue')
        elif choice is 6:
            test.dns.analyze()







if __name__ == '__main__':
    main()
