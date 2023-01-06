#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Android SMS call history plugin."""

import unittest

from plaso.parsers.sqlite_plugins import android_calls

from tests.parsers.sqlite_plugins import test_lib


class AndroidCallSQLitePluginTest(test_lib.SQLitePluginTestCase):
  """Tests for the Android Call History database plugin."""

  def testProcess(self):
    """Test the Process function on an Android contacts2.db file."""
    plugin = android_calls.AndroidCallPlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(['contacts2.db'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 3)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'call_type': 3,
        'data_type': 'android:event:call',
<<<<<<< HEAD
        'date_time': '2013-11-06T21:17:16.690+00:00',
=======
        'duration': 0,
        'end_time': None,
>>>>>>> origin/main
        'number': '5404561685',
        'start_time': '2013-11-06T21:17:16.690+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'android:event:call',
        'date_time': '2013-11-07T00:03:36.690+00:00'}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

    expected_event_values = {
        'data_type': 'android:event:call',
        'date_time': '2013-11-07T00:14:15.690+00:00',
        'duration': 639,
        'timestamp_desc': 'Call Ended'}

    self.CheckEventValues(storage_writer, events[4], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
