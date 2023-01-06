#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Popularity Contest (popcontest) text parser plugin."""

import unittest

from plaso.parsers.text_plugins import popcontest

from tests.parsers.text_plugins import test_lib


class PopularityContestTextPluginTest(test_lib.TextPluginTestCase):
  """Tests for the Popularity Contest (popcontest) text parser plugin."""

  def testProcess(self):
    """Tests the Process function."""
    plugin = popcontest.PopularityContestTextPlugin()
    storage_writer = self._ParseTextFileWithPlugin(['popcontest1.log'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 12)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
<<<<<<< HEAD
        'data_type': 'popularity_contest:session:event',
        'date_time': '2010-06-22T05:41:41+00:00',
        'details': 'ARCH:i386 POPCONVER:1.38',
        'hostid': '12345678901234567890123456789012',
        'session': '0',
        'status': 'start',
        'timestamp_desc': definitions.TIME_DESCRIPTION_ADDED}

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-06-22T07:34:42+00:00',
=======
        'access_time': '2010-06-22T07:34:42+00:00',
        'change_time': '2010-04-06T12:25:42+00:00',
        'data_type': 'linux:popularity_contest_log:entry',
>>>>>>> origin/main
        'mru': '/usr/sbin/atd',
        'package': 'at'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
<<<<<<< HEAD
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-06-22T07:34:43+00:00',
        'mru': '/usr/lib/python2.5/lib-dynload/_struct.so',
        'package': 'python2.5-minimal',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-05-30T05:26:20+00:00',
        'mru': '/usr/bin/empathy',
        'package': 'empathy',
        'record_tag': 'RECENT-CTIME',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[5], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-05-30T05:27:43+00:00',
        'mru': '/usr/bin/empathy',
        'package': 'empathy',
        'record_tag': 'RECENT-CTIME',
        'timestamp_desc': definitions.TIME_DESCRIPTION_METADATA_MODIFICATION}

    self.CheckEventValues(storage_writer, events[6], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-05-12T07:58:33+00:00',
        'mru': '/usr/bin/orca',
        'package': 'gnome-orca',
        'record_tag': 'OLD',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[11], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:session:event',
        'date_time': '2010-06-22T05:41:41+00:00',
        'session': '0',
        'status': 'end',
        'timestamp_desc': definitions.TIME_DESCRIPTION_ADDED}

    self.CheckEventValues(storage_writer, events[13], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:session:event',
        'date_time': '2010-06-22T05:41:41+00:00',
=======
        'data_type': 'linux:popularity_contest_log:session',
        'end_time': '2010-06-22T05:41:41+00:00',
>>>>>>> origin/main
        'details': 'ARCH:i386 POPCONVER:1.38',
        'host_identifier': '12345678901234567890123456789012',
        'session': 0,
        'start_time': '2010-06-22T05:41:41+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[14], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-06-22T07:34:42+00:00',
        'mru': '/super/cool/plasuz',
        'package': 'plaso',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[15], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-04-06T12:25:42+00:00',
        'mru': '/super/cool/plasuz',
        'package': 'miss_ctime',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[18], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:log:event',
        'date_time': '2010-05-12T07:58:33+00:00',
        'mru': '/super/cóól',
        'package': 'plaso',
        'record_tag': 'WRONG_TAG',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS}

    self.CheckEventValues(storage_writer, events[19], expected_event_values)

    expected_event_values = {
        'data_type': 'popularity_contest:session:event',
        'date_time': '2010-06-22T05:41:41+00:00',
        'session': '1',
        'status': 'end',
        'timestamp_desc': definitions.TIME_DESCRIPTION_ADDED}

    self.CheckEventValues(storage_writer, events[21], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 6)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
