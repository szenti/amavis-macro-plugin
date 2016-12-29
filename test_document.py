#!/usr/bin/env python

import unittest
from mock import patch, MagicMock, Mock
import logging
import magic
import os
import subprocess

from document import Document

CONTENT_TYPES = {
    '.docm': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}


class TestDocument(unittest.TestCase):
    def setUp(self):
        super(TestDocument, self).setUp()
        self.logger = logging.getLogger('document')
        self._logger_error = self.logger.error
        self._logger_info = self.logger.info

        self._exists = os.path.exists
        self._isfile = os.path.isfile
        self._from_file = magic.Magic.from_file

        os.path.exists = MagicMock(return_value=True)
        os.path.isfile = MagicMock(return_value=True)

    def tearDown(self):
        self.logger.error = self._logger_error
        self.logger.info = self._logger_info
        magic.Magic.from_file = self._from_file

        os.path.exists = self._exists
        os.path.isfile = self._isfile

    def test_check_FileWithNonXmlContent_ShouldLogClean(self):
        self.logger.info = MagicMock()
        magic.Magic.from_file = MagicMock(return_value='text/plain; charset=us-ascii')

        Document('something.txt').check()

        assert isinstance(self.logger.info, MagicMock)
        self.logger.info.assert_called_once_with('something.txt OK')

    def test_check_NonexistentFile_LogsError(self):
        self.logger.error = Mock()
        magic.Magic.from_file = Mock(
            side_effect=IOError("[Errno 2] No such file or directory: 'nonexistent.file'"))
        os.path.exists = Mock(return_value=False)

        Document('nonexistent.file').check()

        assert isinstance(self.logger.error, Mock)
        self.logger.error.assert_called_once_with('File nonexistent.file does not exist')

    @patch('subprocess.Popen')
    def test_check_ContainsAutoExecutableMacro_LogsError(self, popen_mock):
        process_mock = Mock()
        process_mock.configure_mock(**{'stdout.read.return_value': '| AutoExec   | AutoOpen'})
        subprocess.Popen.return_value = process_mock

        self._setup_macro_mocks()

        Document('document_with_vba.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_called_once_with('/usr/local/bin/olevba document_with_vba.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains auto executable macro')

    @patch('subprocess.Popen')
    def test_check_ContainsAutoExecutableMacro_LogsError(self, popen_mock):
        self._setup_popen_mock('| AutoExec   | AutoOpen')
        self._setup_macro_mocks()

        Document('autoexec.doc').check()

        subprocess.Popen.assert_called_once_with('/usr/local/bin/olevba -a autoexec.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute automatically')

    def _setup_macro_mocks(self):
        magic.Magic.from_file = Mock(return_value='application/vnd.ms-excel')
        self.logger.error = Mock()

    def _setup_popen_mock(self, return_value):
        process_mock = Mock()
        process_mock.configure_mock(**{'stdout.read.return_value': return_value})
        subprocess.Popen.return_value = process_mock

    @patch('subprocess.Popen')
    def test_check_ContainsCommandExecutionMacro_LogsError(self, popen_mock):
        self._setup_popen_mock('| Suspicious | Shell')
        self._setup_macro_mocks()

        Document('shell.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_called_once_with('/usr/local/bin/olevba -a shell.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsFileDownloaderMacro_LogsError(self, popen_mock):
        self._setup_popen_mock('| Suspicious | User-Agent')
        self._setup_macro_mocks()

        Document('downloader.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_called_once_with('/usr/local/bin/olevba -a downloader.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that download file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsMultipleMacros_LogsAllFlags(self, popen_mock):
        self._setup_popen_mock('| AutoExec   | AutoOpen' + "\n" + '| Suspicious | User-Agent')
        self._setup_macro_mocks()

        Document('multiple_flags.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_called_once_with('/usr/local/bin/olevba -a multiple_flags.doc', shell=True,
                                                 stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.logger.error.assert_called_once_with(
            'VIRUS Contains macro(s) that execute automatically, download file(s)')


if __name__ == '__main__':
    unittest.main()
