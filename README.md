# amavis-mmd-detector
An Amavis antivirus plugin for detecting malicious macros in Microsoft
Office documents

## Prerequisites
* python 2.7
* python-magic 0.4.12
* olevba from oletools 0.50

## Installation
Add the following to the amavis config file
(/etc/amavis/conf.d/15-av_scanners in Ubuntu).
```perl
['MED Detector',
   '/usr/local/bin/detect-mde.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```
