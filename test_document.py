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


# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
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

        self.logger.error = Mock()

        file_name = 'document_with_vba.doc'
        Document(file_name).check()

        assert isinstance(subprocess.Popen, Mock)
        self._assert_popen_call(self._setup_file_call(file_name))
        self._assert_popen_call(self._setup_olevba_call(file_name))
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute automatically')

    @staticmethod
    def _assert_popen_call(command):
        parameters = {"shell": True, "stderr": subprocess.PIPE, "stdout": subprocess.PIPE}

        assert isinstance(subprocess.Popen, Mock)
        subprocess.Popen.assert_any_call(command, **parameters)

    @staticmethod
    def _setup_file_call(file_name):
        return '/usr/bin/file --brief --mime {0}'.format(file_name)

    @staticmethod
    def _setup_olevba_call(file_name):
        return '/usr/local/bin/olevba -a {0}'.format(file_name)

    @patch('subprocess.Popen')
    def test_check_ContainsAutoExecutableMacro_LogsError(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| AutoExec   | AutoOpen')
        subprocess.Popen.side_effect = self._side_effect

        file_name = 'autoexec.doc'
        Document(file_name).check()

        self._assert_popen_call(self._setup_olevba_call(file_name))
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

        file_name = 'shell.doc'
        Document(file_name).check()

        self._assert_popen_call(self._setup_olevba_call(file_name))
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that execute file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsFileDownloaderMacro_LogsError(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| Suspicious   | User-Agent')
        subprocess.Popen.side_effect = self._side_effect

        file_name = 'downloader.doc'
        Document(file_name).check()

        self._assert_popen_call(self._setup_olevba_call(file_name))
        self.logger.error.assert_called_once_with('VIRUS Contains macro(s) that download file(s)')

    @patch('subprocess.Popen')
    def test_check_ContainsMultipleMacros_LogsMultipleFlags(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| AutoExec   | AutoOpen' + "\n" + '| Suspicious | User-Agent')
        subprocess.Popen.side_effect = self._side_effect

        file_name = 'multiple_flags.doc'
        Document(file_name).check()

        self._assert_popen_call(self._setup_olevba_call(file_name))
        self.logger.error.assert_called_once_with(
            'VIRUS Contains macro(s) that execute automatically, download file(s)')

    @patch('subprocess.Popen')
    def test_check_NonOfficeFile_SkipChecking(self, popen_mock):
        self._setup_popen_mock('ASCII text')

        file_name = 'example.txt'
        Document(file_name).check()

        self._assert_popen_call(self._setup_file_call(file_name))


    @patch('subprocess.Popen')
    def test_check_HideDetailsTrue_LogsErrorWithoutFlags(self, popen_mock):
        self.logger.error = Mock()

        self._setup_popen_mock('application/vnd.ms-excel')
        self._setup_popen_mock('| Suspicious   | User-Agent')
        subprocess.Popen.side_effect = self._side_effect

        file_name = 'dangerous_macro.doc'
        Document(file_name, True).check()

        self._assert_popen_call(self._setup_olevba_call(file_name))
        self.logger.error.assert_called_once_with('VIRUS Dangerous macro')


if __name__ == '__main__':
    unittest.main()
