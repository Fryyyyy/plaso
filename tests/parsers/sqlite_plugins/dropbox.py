#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Dropbox sync_history database plugin."""

import unittest

from plaso.parsers.sqlite_plugins import dropbox

from tests.parsers.sqlite_plugins import test_lib


class DropboxSyncHistoryPluginTest(test_lib.SQLitePluginTestCase):
  """Tests for the Dropbox sync_history database plugin."""

  def testProcess(self):
    """Tests the Process function on a Dropbox sync_history database file."""
    plugin = dropbox.DropboxSyncDatabasePlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['sync_history.db'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 6)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
<<<<<<< HEAD
        'date_time': '2022-02-17T10:57:18+00:00',
=======
>>>>>>> origin/main
        'direction': 'upload',
        'event_type': 'file',
        'file_event_type': 'add',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAAGg',
        'local_path': '/home/useraa/Dropbox/loc1/create_local.txt',
<<<<<<< HEAD
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
        'date_time': '2022-02-17T10:57:19+00:00',
        'direction': 'upload',
        'event_type': 'file',
        'file_event_type': 'delete',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAAKg',
        'local_path': '/home/useraa/Dropbox/loc1/.create_local.txt.swp',
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[1], expected_event_values)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
        'date_time': '2022-02-17T11:01:21+00:00',
        'direction': 'download',
        'event_type': 'file',
        'file_event_type': 'add',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAAKw',
        'local_path': '/home/useraa/Dropbox/web1/create_web.txt',
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[2], expected_event_values)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
        'date_time': '2022-02-17T11:04:03+00:00',
        'direction': 'download',
        'event_type': 'file',
        'file_event_type': 'delete',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAALA',
        'local_path': '/home/useraa/Dropbox/web2/create_web.txt',
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
        'date_time': '2022-02-17T11:05:50+00:00',
        'direction': 'download',
        'event_type': 'file',
        'file_event_type': 'edit',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAALQ',
        'local_path': '/home/useraa/Dropbox/web2/Document.docx',
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[4], expected_event_values)

    expected_event_values = {
        'data_type': 'dropbox:sync_history:entry',
        'date_time': '2022-02-17T11:06:34+00:00',
        'direction': 'download',
        'event_type': 'file',
        'file_event_type': 'add',
        'file_identifier': 'XXXXXXXXXXXAAAAAAAAALg',
        'local_path': '/home/useraa/Dropbox/web2/Untitled.gdoc',
        'timestamp_desc': definitions.TIME_DESCRIPTION_RECORDED}

    self.CheckEventValues(storage_writer, events[5], expected_event_values)
=======
        'recorded_time': '2022-02-17T10:57:18+00:00'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
