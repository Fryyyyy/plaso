#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Apple Unified Logging parser."""

import unittest

from plaso.parsers import aul

from tests.parsers import test_lib


class AULParserTest(test_lib.ParserTestCase):
    """Tests for the AUL parser."""

    def testParse(self):
        """Tests the Parse function."""
        parser = aul.AULParser()
        storage_writer = self._ParseFile([
            'AUL', 'private', 'var', 'db', 'diagnostics', 'Special',
            '0000000000000346.tracev3'
        ], parser)

        number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
        self.assertEqual(number_of_events, 8)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            'extraction_warning')
        self.assertEqual(number_of_warnings, 0)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            'recovery_warning')
        self.assertEqual(number_of_warnings, 0)

        events = list(storage_writer.GetEvents())

        expected_event_values = {
            'data_type': 'chrome:cache:entry',
            'date_time': '2014-04-30 16:44:36.226091',
            'boot_uuid': '61D6D89537BB4363A7F401F8E4DD1BC8'}

        self.CheckEventValues(storage_writer, events[0], expected_event_values)


if __name__ == '__main__':
    unittest.main()
