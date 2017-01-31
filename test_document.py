#!/usr/bin/env python

import unittest
from mock import patch, MagicMock, Mock
import logging
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

        os.path.exists = MagicMock(return_value=True)
        os.path.isfile = MagicMock(return_value=True)
        self._side_effect = []

    def tearDown(self):
        self.logger.error = self._logger_error
        self.logger.info = self._logger_info

        os.path.exists = self._exists
        os.path.isfile = self._isfile

    def test_check_FileWithNonXmlContent_ShouldLogClean(self):
        self.logger.info = MagicMock()

        Document('something.txt').check()

        assert isinstance(self.logger.info, MagicMock)
        self.logger.info.assert_called_once_with('something.txt OK')

    def test_check_NonexistentFile_LogsError(self):
        self.logger.error = Mock()
        # magic.Magic.from_file = Mock(
        #     side_effect=IOError("[Errno 2] No such file or directory: 'nonexistent.file'"))
        os.path.exists = Mock(return_value=False)

        Document('nonexistent.file').check()

        assert isinstance(self.logger.error, Mock)
        self.logger.error.assert_called_once_with('File nonexistent.file does not exist')

    @patch('subprocess.Popen')
    def test_check_ContainsAutoExecutableMacro2_LogsError(self, popen_mock):
        olevba_mock = Mock()
        olevba_mock.configure_mock(**{'stdout.read.return_value': '| AutoExec   | AutoOpen'})

        file_mock = Mock()
        file_mock.configure_mock(**{'stdout.read.return_value': 'application/vnd.ms-excel'})
        subprocess.Popen.side_effect = [file_mock, olevba_mock]

        # self._setup_macro_mocks()
        self.logger.error = Mock()

        Document('document_with_vba.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_any_call('/usr/bin/file --brief --mime document_with_vba.doc', shell=True, stderr=-1, stdout=-1)
        subprocess.Popen.assert_any_call('/usr/local/bin/olevba -a document_with_vba.doc', shell=True, stderr=-1, stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute automatically')

    @patch('subprocess.Popen')
    def test_check_ContainsAutoExecutableMacro_LogsError(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| AutoExec   | AutoOpen')
        subprocess.Popen.side_effect = self._side_effect

        Document('autoexec.doc').check()

        subprocess.Popen.assert_any_call('/usr/local/bin/olevba -a autoexec.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute automatically')

    def _setup_macro_mocks(self):
        olevba_mock = Mock()
        olevba_mock.configure_mock(**{'stdout.read.return_value': '| AutoExec   | AutoOpen'})
        self._side_effect.append(olevba_mock)

    def _setup_popen_mock(self, return_value):
        process_mock = Mock()
        process_mock.configure_mock(**{'stdout.read.return_value': return_value})
        self._side_effect.append(process_mock)

    @patch('subprocess.Popen')
    def test_check_ContainsCommandExecutionMacro_LogsError(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| Suspicious   | Shell')
        subprocess.Popen.side_effect = self._side_effect

        Document('shell.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_any_call('/usr/local/bin/olevba -a shell.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsFileDownloaderMacro_LogsError(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| Suspicious   | User-Agent')
        subprocess.Popen.side_effect = self._side_effect

        Document('downloader.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_any_call('/usr/local/bin/olevba -a downloader.doc', shell=True, stderr=-1,
                                                 stdout=-1)
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that download file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsMultipleMacros_LogsAllFlags(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| AutoExec   | AutoOpen' + "\n" + '| Suspicious | User-Agent')
        subprocess.Popen.side_effect = self._side_effect

        Document('multiple_flags.doc').check()

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_any_call('/usr/local/bin/olevba -a multiple_flags.doc', shell=True,
                                                 stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.logger.error.assert_called_once_with(
            'VIRUS Contains macro(s) that execute automatically, download file(s)')

    @patch('subprocess.Popen')
    def test_check_NonOfficeFile_SkipChecking(self, popen_mock):
        self._setup_popen_mock('ASCII text')

        Document('example.txt').check()

        subprocess.Popen.assert_called_once_with('/usr/bin/file --brief --mime example.txt', shell=True, stderr=-1,
                                                 stdout=-1)


if __name__ == '__main__':
    unittest.main()
