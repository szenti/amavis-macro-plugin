# Overview
The Amavis Malicious Macro Detector (mmd) is an Amavis AV plugin for detecting
Malicious Office Macros in the attached files of e-mails. It uses the
olevba script from the oletools Python package to determine the
characteristics of the macros in the Office documents.

## Filtering characteristics
Any office document that contains macros that meet any of the
characteristics below will be treated as infected:

* AutoStart - Starts macros on opening/closing/saving the document
* Shell - Executed files
* User Agent - Downloads file(s), and/or executes web requests

## Prerequisites

* python 2.7
* oletools 0.50
* file (Unix utility to determine mime-type)

# Installing and configuring

The installation of the Macro Detector requires the following steps.

* Installing oletools
* Installing mmd
* Configuring mmd
* Integrating into Amavis

## Installing oletools

To install oletools, execute the following command:
```shell
sudo -H pip install -U oletools
```

_Verification_: {TODO}

## Installing mmd

Copy the files **mmd.py**, **document.py** and **document_config.json**
to /usr/local/bin, then change the file permissions for enabling the
amavis user to execute the script.

You can also use the attached install.sh to do the copy and permission
setup. Please note that the script contains Ubuntu Server specific
paths.
```shell
wget --no-check-certificate https://github.com/szenti/amavis-macro-plugin/archive/master.zip
unzip master.zip

sudo ./install.sh
```

_Verification_: {TODO}


## Configuring mmd

Macro detector contains three configuration options, which are stored in
the document_config.json file.

* Paths to utilities
  * unix file
  * olevba script
* Logging: hide detailed information (hide_details)


### Paths

Paths to _file_, and _olevba_ utilities.

### Logging: hide detailed information (hide_details)

This option is used to hide detailed information from the output. If
it's set to _false_, **mmd** will output the found macro
characteristics.

For example, if you are using postfix's before queue filtering, this
would leak information about the detected macro characteristics back to
the sender. If it's set to _true_ (recommended, default), mmd will only
output a generic _Dangerous macro_ message.

Default value: _true_

## Integrating into Amavis

(Ubuntu Server): add the following to the amavis config file:
/etc/amavis/conf.d/15-av_scanners
```perl
['Malicious Macro Detector',
   '/usr/local/bin/mmd.py', "{}",
      [0], qr/VIRUS/, qr/\bVIRUS (.+)\b/m ],
```

Restart the amavis service (Ubuntu Server 14.04):
```shell
# service amavis restart
```

_Verification_: {TODO}

# Verification

{TODO}