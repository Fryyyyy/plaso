#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the iOS sysdiagnose logd files (logd.0.log) text parser plugin."""

import unittest

from plaso.parsers.text_plugins import ios_logd

from tests.parsers.text_plugins import test_lib


class IOSSysdiagnoseLogdUnitTest(test_lib.TextPluginTestCase):
  """Tests for the iOS sysdiagnose logd files (logd.0.log) text plugin."""

  def testProcess(self):
    """Tests the Process function."""
    plugin = ios_logd.IOSSysdiagnoseLogdTextPlugin()
    storage_writer = self._ParseTextFileWithPlugin(['logd.0.log'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 76)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'body': 'libtrace_kic=1',
        'data_type': 'ios:sysdiagnose:logd:line',
<<<<<<< HEAD
        'date_time': '2021-08-11T05:50:23+07:00',
=======
>>>>>>> origin/main
        'logger': 'logd[29]',
        'written_time': '2021-08-11T05:50:23-07:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[2], expected_event_values)

    expected_event_values = {
        'body': 'Harvesting: 9227BC73-2AF5-318F-AA62-DCBE2219DBC8',
        'data_type': 'ios:sysdiagnose:logd:line',
        'date_time': '2021-10-13T08:41:02+04:00',
        'logger': 'logd_helper[90]',
        'timestamp': '2021-10-13 04:41:02.000000'}

    self.CheckEventValues(storage_writer, events[29], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 2)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
