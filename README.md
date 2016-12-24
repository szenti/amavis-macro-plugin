# amavis-med-detector
An Amavis antivirus plugin for detecting **m**acro **e**nabled **o**ffice documents
(.doc, .xls, .docm, .xlsm).

## Prerequisites
* python 2.7
* python-magic 0.4.12

## Installation
Add the following to the amavis config file
(/etc/amavis/conf.d/15-av_scanners).
```perl
['MED Detector',
   '/usr/local/bin/detect-mde.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```
