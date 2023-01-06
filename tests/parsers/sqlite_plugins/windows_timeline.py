#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Windows Timeline SQLite database plugin."""

import unittest

from plaso.parsers.sqlite_plugins import windows_timeline

from tests.parsers.sqlite_plugins import test_lib


class WindowsTimelineTest(test_lib.SQLitePluginTestCase):
  """Tests for the Windows Timeline plugin."""

  def testProcess(self):
    """Tests the Process function on a Windows Timeline SQLite database."""
    plugin = windows_timeline.WindowsTimelinePlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['windows_timeline_ActivitiesCache.db'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 112)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'active_duration_seconds': 9,
        'data_type': 'windows:timeline:user_engaged',
<<<<<<< HEAD
        'date_time': '2018-08-03T11:29:00+00:00',
=======
>>>>>>> origin/main
        'package_identifier': 'c:\\python34\\python.exe',
        'reporting_app': 'ShellActivityMonitor',
        'start_time': '2018-08-03T11:29:00+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'active_duration_seconds': 11,
        'data_type': 'windows:timeline:user_engaged',
        'date_time': '2018-07-27T11:58:55+00:00',
        'package_identifier': (
            'c:\\users\\demouser\\appdata\\local\\programs\\python\\'
            'python37-32\\python.exe'),
        'reporting_app': 'ShellActivityMonitor',
        'timestamp_desc': definitions.TIME_DESCRIPTION_START}

    self.CheckEventValues(storage_writer, events[2], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main

    expected_event_values = {
        'application_display_name': 'OneDrive',
        'data_type': 'windows:timeline:generic',
<<<<<<< HEAD
        'date_time': '2018-07-25T12:04:48+00:00',
        'description': '',
=======
        'description': None,
>>>>>>> origin/main
        'package_identifier': 'Microsoft.SkyDrive.Desktop',
        'start_time': '2018-07-25T12:04:48+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[80], expected_event_values)

    expected_event_values = {
        'application_display_name': 'Notepad',
        'data_type': 'windows:timeline:generic',
        'date_time': '2018-07-27T12:36:09+00:00',
        'description': 'C:\\Users\\demouser\\Desktop\\SCHEMA.txt',
        'package_identifier': (
            '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe'),
        'timestamp_desc': definitions.TIME_DESCRIPTION_START}

    self.CheckEventValues(storage_writer, events[96], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 80)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
