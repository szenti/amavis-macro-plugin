# amavis-med-detector
An Amavis antivirus plugin for detecting **m**acro **e**nabled **o**ffice documents
(.doc, .xls, .docm, .xlsm).

## Prerequisites
* python 2.7
* python-magic 0.4.12

## Installation
Modify
```perl
['MED Detector',
   '/usr/local/bin/detect-mde.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```
