#!/usr/bin/env python

import unittest
from document import Document

from mock import patch, MagicMock
import logging
import magic
import sys
import os

CONTENT_TYPES = {
    '.docm': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}


class TestDocument(unittest.TestCase):
    def setUp(self):
        super(TestDocument, self).setUp()
        self.logger = logging.getLogger('document')
        self.logger_error = self.logger.error
        self.logger_info = self.logger.info

        self.from_file = magic.Magic.from_file
        self.sys_exit = sys.exit
        self.mock_exists = os.path.exists

        magic.Magic.from_file = MagicMock(return_value='')
        sys.exit = MagicMock()
        os.path.exists = MagicMock(return_value=True)

    def tearDown(self):
        magic.Magic.from_file = self.from_file
        sys.exit = self.sys_exit
        os.path.exists = self.mock_exists

        self.logger.error = self.logger_error
        self.logger.info = self.logger_info

    def test_check_FileWithNonXmlContent_ShouldLogClean(self):
        self.logger.info = MagicMock()
        magic.Magic.from_file = MagicMock(return_value='text/plain; charset=us-ascii')

        Document('something.txt').check()

        assert isinstance(self.logger.info, MagicMock)
        self.logger.info.assert_called_once_with('OK')

    def test_check_NonexistentFile_LogsError(self):
        self.logger.error = MagicMock()
        magic.Magic.from_file = MagicMock(
            side_effect=IOError("[Errno 2] No such file or directory: 'nonexistent.file'"))
        os.path.exists = MagicMock(return_value=False)

        Document('nonexistent.file').check()

        assert isinstance(self.logger.error, MagicMock)
        self.logger.error.assert_called_once_with('File nonexistent.file does not exist')

    def test_check_NonOpenXMLFileExtensionWithOpenXMLContent_LogsError(self):
        magic.Magic.from_file = MagicMock(return_value=CONTENT_TYPES['.docm'])
        self.logger.error = MagicMock()

        Document('/tmp/somefile.doc').check()

        self.logger.error.assert_called_once_with('VIRUS File somefile.doc has openxml content')

    def test_check_OpenXMLFileExtensionWithOpenXMLContent_DoesNotLogError(self):
        magic.Magic.from_file = MagicMock(return_value=CONTENT_TYPES['.docm'])
        self.logger.error = MagicMock()

        Document('/tmp/otherfile.docm').check()

        assert isinstance(self.logger.error, MagicMock)
        self.logger.error.assert_not_called()


if __name__ == '__main__':
    unittest.main()
