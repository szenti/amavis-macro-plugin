#!/usr/bin/env python

import magic
import os
import sys
import logging


class InvalidContentError(RuntimeError):
    pass


MIME_TYPE_ALLOWED_EXTENSIONS = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ['.docx', '.docm'],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ['.xlsx', '.xlsm'],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ['.pptx', '.pptm']
}


class Document:
    def __init__(self, filename):
        self._file_path = filename
        self._file_name, self._extension = os.path.splitext(os.path.split(filename)[1])
        self._file_name += self._extension

        self._magic = magic.Magic(mime=True)
        self._setup_logging()

    def _setup_logging(self):
        self._logger = logging.getLogger('document')
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self._logger.addHandler(console_handler)

    def check(self):
        try:
            self._check_file_exists()
            self._check_extension_differs_from_content(self._get_type())
            self._log_clean()
        except:
            sys.exit(1)

    def _check_file_exists(self):
        if not os.path.exists(self._file_path):
            self._logger.error('File {0} does not exist'.format(self._file_path))
            raise IOError('File does not exist')

    def _get_type(self):
        return self._magic.from_file(self._file_path)

    def _check_extension_differs_from_content(self, file_type):
        if file_type not in MIME_TYPE_ALLOWED_EXTENSIONS:
            return

        if self._extension.lower() not in MIME_TYPE_ALLOWED_EXTENSIONS[file_type]:
            self._logger.error('VIRUS File {0} has openxml content'.format(self._file_name))
            raise InvalidContentError('File has openxml content')

    def _log_clean(self):
        self._logger.info('OK')
