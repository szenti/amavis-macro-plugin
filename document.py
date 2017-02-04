#!/usr/bin/env python

import os
import sys
import logging
import subprocess
import re
from collections import OrderedDict

COMMAND_PATH = {
    'file': '/usr/bin/file',
    'olevba': '/usr/local/bin/olevba'
}

MIME_TYPES_TO_CHECK = [
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/msword',
    'application/vnd.ms-excel',
    'application/vnd.ms-office'
]


class Document:
    __logger = None
    __macro_flags = {}

    def __init__(self, filename):
        self._file_path = filename
        self._file_name, self._extension = os.path.splitext(os.path.split(filename)[1])
        self._file_name += self._extension

    @property
    def _logger(self):
        if Document.__logger is None:
            Document.__logger = logging.getLogger('document')
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(message)s'))
            Document.__logger.addHandler(console_handler)
            Document.__logger.setLevel(logging.WARNING)

        return Document.__logger

    @property
    def _macro_flags(self):
        if not Document.__macro_flags:
            self._setup_flags()

        return Document.__macro_flags

    def _setup_flags(self):
        compiled = self._compile_regular_expressions()
        flags = ['execute automatically', 'execute file(s)', 'download file(s)']
        Document.__macro_flags = OrderedDict(zip(compiled, flags))

    def _compile_regular_expressions(self):
        patterns = ('AutoExec', "Suspicious\s+\|\s+Shell", "Suspicious\s+\|\s+User-Agent")
        compiled = [re.compile("^\|\s+" + exp, re.MULTILINE) for exp in patterns]
        return compiled

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
        command = '{0} --brief --mime {1}'.format(COMMAND_PATH['file'], self._file_path)
        output = self._get_command_output(command)

        return output.lower()

    def _log_clean(self):
        self._logger.info('{0} OK'.format(self._file_name))

    def _check_contains_malicious_macro(self):
        document_type = self._get_type()

        for mime_type in MIME_TYPES_TO_CHECK:
            if mime_type in document_type:
                self._check_macro_flags()
                break

    def _check_macro_flags(self):
        params = COMMAND_PATH['olevba'] +' -a {0}'.format(self._file_path)
        output = self._get_command_output(params)
        flags = self.__compute_macro_flags(output)

        if flags:
            self._logger.error('VIRUS Contains macro(s) that ' + ', '.join(flags))

    def _get_command_output(self, command):
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        return process.stdout.read()

    def __compute_macro_flags(self, output):
        flags = []
        for regexp in self._macro_flags.keys():
            if regexp.findall(output):
                flags.append(self._macro_flags[regexp])
        return flags


class SkipChecks(RuntimeError):
    pass
