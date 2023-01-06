#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Java Cache IDX file parser."""

import unittest

from plaso.parsers import java_idx

from tests.parsers import test_lib


class IDXTest(test_lib.ParserTestCase):
  """Tests for Java Cache IDX file parser."""

  def testParse602(self):
    """Tests the Parse function on a version 602 IDX file."""
    parser = java_idx.JavaIDXParser()
    storage_writer = self._ParseFile(['java_602.idx'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 1)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'java:download:idx',
<<<<<<< HEAD
        'date_time': '2010-05-05T01:34:19.720+00:00',
=======
        'downloaded_time': '2010-05-05T03:52:31+00:00',
        'modification_time': '2010-05-05T01:34:19.720+00:00',
>>>>>>> origin/main
        'idx_version': 602,
        'url': 'http://www.gxxxxx.com/a/java/xxz.jar'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    # Parse second event. Same metadata; different timestamp event.
    expected_event_values = {
        'data_type': 'java:download:idx',
        'date_time': '2010-05-05T03:52:31+00:00',
        'idx_version': 602,
        'timestamp_desc': definitions.TIME_DESCRIPTION_FILE_DOWNLOADED,
        'url': 'http://www.gxxxxx.com/a/java/xxz.jar'}

    self.CheckEventValues(storage_writer, events[1], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main

  def testParse605(self):
    """Tests the Parse function on a version 605 IDX file."""
    parser = java_idx.JavaIDXParser()
    storage_writer = self._ParseFile(['java.idx'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 1)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'java:download:idx',
<<<<<<< HEAD
        'date_time': '2001-07-26T05:00:00.000+00:00',
=======
        'downloaded_time': '2013-01-13T16:22:01+00:00',
        'modification_time': '2001-07-26T05:00:00.000+00:00',
>>>>>>> origin/main
        'idx_version': 605,
        'ip_address': '10.7.119.10',
        'url': (
            'http://xxxxc146d3.gxhjxxwsf.xx:82/forum/dare.php?'
            'hsh=6&key=b30xxxx1c597xxxx15d593d3f0xxx1ab')}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    # Parse second event. Same metadata; different timestamp event.
    expected_event_values = {
        'data_type': 'java:download:idx',
        'date_time': '2013-01-13T16:22:01+00:00',
        'idx_version': 605,
        'ip_address': '10.7.119.10',
        'timestamp_desc': definitions.TIME_DESCRIPTION_FILE_DOWNLOADED,
        'url': (
            'http://xxxxc146d3.gxhjxxwsf.xx:82/forum/dare.php?'
            'hsh=6&key=b30xxxx1c597xxxx15d593d3f0xxx1ab')}

    self.CheckEventValues(storage_writer, events[1], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
