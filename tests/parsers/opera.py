#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Opera browser history parsers."""

import unittest

from plaso.parsers import opera

from tests.parsers import test_lib


class OperaTypedParserTest(test_lib.ParserTestCase):
  """Tests for the Opera Typed History parser."""

  def testParse(self):
    """Tests the Parse function."""
    parser = opera.OperaTypedHistoryParser()
    storage_writer = self._ParseFile(['typed_history.xml'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 4)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'opera:history:typed_entry',
<<<<<<< HEAD
        'date_time': '2013-11-11T23:45:27+00:00',
=======
>>>>>>> origin/main
        'entry_selection': 'Filled from autocomplete.',
        'last_typed_time': '2013-11-11T23:45:27+00:00',
        'url': 'plaso.kiddaland.net'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'opera:history:typed_entry',
        'date_time': '2013-11-11T22:46:07+00:00',
        'entry_selection': 'Manually typed.',
        'url': 'theonion.com'}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


class OperaGlobalParserTest(test_lib.ParserTestCase):
  """Tests for the Opera Global History parser."""

  def testParseFile(self):
    """Read a history file and run a few tests."""
    parser = opera.OperaGlobalHistoryParser()
    storage_writer = self._ParseFile(['global_history.dat'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 37)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'opera:history:entry',
<<<<<<< HEAD
        'date_time': '2013-11-11T22:45:46+00:00',
=======
>>>>>>> origin/main
        'description': 'First and Only Visit',
        'last_visited_time': '2013-11-11T22:45:46+00:00',
        'title': 'Karl Bretaprins fær ellilífeyri - mbl.is',
        'url': (
            'http://www.mbl.is/frettir/erlent/2013/11/11/'
            'karl_bretaprins_faer_ellilifeyri/')}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[4], expected_event_values)

    expected_event_values = {
        'data_type': 'opera:history:entry',
        'date_time': '2013-11-11T22:45:55+00:00'}

    self.CheckEventValues(storage_writer, events[10], expected_event_values)

    expected_event_values = {
        'data_type': 'opera:history:entry',
        'date_time': '2013-11-11T22:46:16+00:00',
        'title': (
            '10 Celebrities You Never Knew Were Abducted And Murdered '
            'By Andie MacDowell | The Onion - America\'s Finest News Source')}

    self.CheckEventValues(storage_writer, events[16], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 4)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
