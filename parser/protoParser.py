#!/usr/bin/env python

import os

class ProtoParser():

    def __init__(self, tempFile):
        self.tempFile = tempFile
        self.preped = False

    def prepOut(self):
        raise NotImplementedError

    def out(self, rmTemp=False):

        if not self.preped:
            self.prepOut()

        if os.path.isfile(self.tempFile):
            os.system("less {}".format(self.tempFile))

        if rmTemp:
            self.cleanUp()
            
        #else:
        #    raise Exception

    def cleanUp(self):
        if os.path.isfile(self.tempFile):
            os.system("rm {}".format(self.tempFile))

def main():
    pass

if __name__ is '__main__':
    main()
