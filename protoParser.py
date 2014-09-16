#!/usr/bin/env python

import os

class ProtoParser():

    def __init__(self, tempFile):
        self.tempFile = tempFile

    def prepOut(self):
        raise NotImplementedError

    def out(self):
        os.system("less {}".format(self.tempFile))
        os.system("rm {}".format(self.tempFile))


def main():
    pass

if __name__ is '__main__':
    main()