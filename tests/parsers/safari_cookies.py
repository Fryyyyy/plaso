#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Safari cookie parser."""

import unittest

from plaso.parsers import safari_cookies

from tests.parsers import test_lib


class SafariCookieParserTest(test_lib.ParserTestCase):
  """Tests for the Safari cookie parser."""

  def testParseFile(self):
    """Tests the Parse function on a Safari binary cookies file."""
    parser = safari_cookies.BinaryCookieParser()
    storage_writer = self._ParseFile(['Cookies.binarycookies'], parser)

    # There should be:
    # * 207 events in total
    # * 182 events from the safari cookie parser
    # * 25 event from the cookie plugins

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 106)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

<<<<<<< HEAD
    events = []
    for event in storage_writer.GetEvents():
      event_data = self._GetEventDataOfEvent(storage_writer, event)
      if event_data.data_type == 'safari:cookie:entry':
        events.append(event)

    self.assertEqual(len(events), 182)

    expected_event_values = {
        'cookie_name': 'GAPS',
        'data_type': 'safari:cookie:entry',
        'date_time': '2015-07-08T20:54:03.000000+00:00',
        'flags': 5,
        'url': 'accounts.google.com'}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

    expected_event_values = {
        'cookie_name': 'nonsession',
        'data_type': 'safari:cookie:entry',
        'date_time': '2013-07-08T20:54:50.000000+00:00',
        'flags': 0,
        'path': '/',
        'timestamp_desc': definitions.TIME_DESCRIPTION_CREATION,
        'url': '.ebay.com'}

    self.CheckEventValues(storage_writer, events[48], expected_event_values)

=======
>>>>>>> origin/main
    expected_event_values = {
        'cookie_name': 'fpc',
        'cookie_value': (
            'd=0dTg3Ou32s3MrAJ2iHjFph100Tw3E1HTfDOTly0GfJ2g4W.mXpy54F9fjBFfXMw'
            '4YyWAG2cT2FVSqOvGGi_Y1OPrngmNvpKPPyz5gIUP6x_EQeM7bR3jsrg_F1UXVOgu'
            '6JgkFwqO5uHrv4HiL05qb.85Bl.V__HZI5wpAGOGPz1XHhY5mOMH.g.pkVDLli36W'
            '2iuYwA-&v=2'),
        'data_type': 'safari:cookie:entry',
<<<<<<< HEAD
        'date_time': '2013-07-08T17:24:30.000000+00:00',
=======
        'expiration_time': '2014-07-08T05:24:29.000000+00:00',
        'creation_time': '2013-07-08T17:24:30.000000+00:00',
>>>>>>> origin/main
        'path': '/',
        'url': '.www.yahoo.com'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 26)
    self.CheckEventData(event_data, expected_event_values)


if __name__ == '__main__':
  unittest.main()
