#!/usr/bin/env python

import magic
import os
import sys
import logging


class SkipChecks(RuntimeError):
    pass


MIME_TYPE_ALLOWED_EXTENSIONS = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ['.docx', '.docm'],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ['.xlsx', '.xlsm'],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ['.pptx', '.pptm']
}


class Document:
    _logger = None

    def __init__(self, filename):
        self._file_path = filename
        self._file_name, self._extension = os.path.splitext(os.path.split(filename)[1])
        self._file_name += self._extension

        self._magic = magic.Magic(mime=True)
        self._setup_logging()

    def _setup_logging(self):
        if Document._logger:
            return

        Document._logger = logging.getLogger('document')
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        Document._logger.addHandler(console_handler)
        Document._logger.setLevel(logging.DEBUG)

    def check(self):
        try:
            self._check_file_exists()
            self._check_extension_differs_from_content(self._get_type())
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

    def _check_extension_differs_from_content(self, file_type):
        if file_type not in MIME_TYPE_ALLOWED_EXTENSIONS:
            return

        if self._extension.lower() not in MIME_TYPE_ALLOWED_EXTENSIONS[file_type]:
            self._logger.error('VIRUS File {0} has openxml content'.format(self._file_name))
            raise SkipChecks()

    def _log_clean(self):
        self._logger.info('{0} OK'.format(self._file_name))
