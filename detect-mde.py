#!/usr/bin/env python

from document import Document
import sys
import os

if len(sys.argv) != 2:
    print "Usage:\n{0} <path to file>".format(os.path.split(sys.argv[0])[1])
    exit(0)

Document(sys.argv[1]).check()
