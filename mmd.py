#!/usr/bin/env python

from document import Document
import sys
import os

if len(sys.argv) != 2:
    print "Usage:\n{0} <path to directory>".format(os.path.split(sys.argv[0])[1])
    exit(0)

path = sys.argv[1]

if not os.path.isdir(path):
    exit(1)

for filename in os.listdir(path):
    file_path = os.path.join(path, filename)
    Document(file_path).check()
