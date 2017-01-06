# Overview
The Amavis Malicious Macro Detector is an Amavis AV plugin for detecting
Malicious Office Macros in the attached files of e-mails. It uses the
olevba script from the oletools Python package to determine the
characteristics of the macros in the Office documents.

## Filtered characteristics
Any office document that contains macros that meet any of the
characteristics below will be treated as infected:

* AutoStart - Starts macros on opening/closing/saving the document
* Shell - Executed files

## Prerequisites

* python 2.7
* python-magic 0.4.12
* oletools 0.50

# Installation

The installation of the Macro Detector requires the following steps.

* Installation of oletools
* Setting up amavis-macro-plugin
* Integration into Amavis (Ubuntu Server 14.04 specific instructions)


### Installation of oletools

To install oletools, execute the following command:
```shell
sudo -H pip install -U oletools
```

_Verification_: {TODO}

### Setting up amavis-macro-plugin

Copy the files mmd.py, document,py to /usr/local/bin, then change
the file permissions for enabling the amavis user to execute the plugin.
```shell
# Ubuntu Server installation instructions, assuming that the user amavis exists

wget --no-check-certificate https://github.com/szenti/amavis-macro-plugin/archive/master.zip
unzip master.zip

for file in mmd.py document.py; do
    dest=/usr/local/bin/${file}
    sudo cp amavis-macro-plugin-master/${file} ${dest}
    sudo chown root:amavis ${dest}
    sudo chmod 755 ${dest}
done
```

_Verification_: {TODO}

### Integrating into Amavis (Ubuntu Server 14.04 specific instructions)

Add the following to the amavis config file (Ubuntu 14.04: /etc/amavis/conf.d/15-av_scanners).
```perl
['Malicious Macro Detector',
   '/usr/local/bin/mmd.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```

Restart the amavis service:
```shell
service amavis restart
```

_Verification_: {TODO}

# Verification

To test the effectiveness of the solution, try to send an email with an attachment of a malicuous macro.
For testing purposes you can use eicar-standard-antivirus-test-file-microsoft-word-macro-cmd-echo.doc file from https://github.com/mattias-ohlsson/eicar-standard-antivirus-test-files/blob/master/eicar-standard-antivirus-test-file-microsoft-word-macro-cmd-echo.doc