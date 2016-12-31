# amavis-macro-plugin
An Amavis AV plugin for detecting Malicious Office Macros in e-mails.

## Prerequisites
* python 2.7
* python-magic 0.4.12
* olevba from oletools 0.50

## Installation
Add the following to the amavis config file
(/etc/amavis/conf.d/15-av_scanners in Ubuntu).
```perl
['Malicious Macro Detector',
   '/usr/local/bin/detect-mde.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```
