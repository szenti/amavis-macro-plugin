#!/usr/bin/env python

import magic
import os
import sys
import logging
import subprocess
import re


class SkipChecks(RuntimeError):
    pass


OFFICE_MIME_TYPES = {
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-office'
}


class Document:
    __logger = None
    __macro_summary = {}

    def __init__(self, filename):
        self._file_path = filename
        self._file_name, self._extension = os.path.splitext(os.path.split(filename)[1])
        self._file_name += self._extension

        self._magic = magic.Magic(mime=True)

    @property
    def _logger(self):
        if not self.__logger:
            self.__logger = logging.getLogger('document')
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            self.__logger.addHandler(console_handler)
            self.__logger.setLevel(logging.WARNING)

        return self.__logger

    @property
    def _macro_flags(self):
        if not self.__macro_summary:
            expressions = [re.compile("^\|\s+" + exp, re.MULTILINE) for exp in
                           ('AutoExec', "Suspicious\s+\|\s+Shell", "Suspicious\s+\|\s+User-Agent")]
            details = ['execute automatically', 'execute file(s)', 'download file(s)']
            self.__macro_summary = dict(zip(expressions, details))

        return self.__macro_summary

    def check(self):
        try:
            self._check_file_exists()
            self._check_contains_malicious_macro()
            self._log_clean()
        except SkipChecks:
            return
        except Exception as ex:
            self._logger.error(ex)
            return

    def _check_file_exists(self):
        if not os.path.exists(self._file_path):
            self._logger.error('File {0} does not exist'.format(self._file_path))
            raise SkipChecks()

        if not os.path.isfile(self._file_path):
            raise SkipChecks()

    def _get_type(self):
        return self._magic.from_file(self._file_path)

    def _log_clean(self):
        self._logger.info('{0} OK'.format(self._file_name))

    def _check_contains_malicious_macro(self):
        type = self._get_type()

        if type in OFFICE_MIME_TYPES:
            self._check_macro_flags()

    def _check_macro_flags(self):
        output = self._execute_command()
        flags = self.__compute_macro_flags(output)

        if flags:
            self._logger.error('VIRUS Contains macro(s) that ' + ', '.join(flags))

    def _execute_command(self):
        command = '/usr/local/bin/olevba -a {0}'.format(self._file_path)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        return process.stdout.read()

    def __compute_macro_flags(self, output):
        flags = []
        for regexp in self._macro_flags.keys():
            if regexp.findall(output):
                flags.append(self._macro_flags[regexp])
        return flags
