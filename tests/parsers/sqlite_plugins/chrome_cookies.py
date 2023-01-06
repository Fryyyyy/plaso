#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Google Chrome cookie database plugin."""

import unittest

from plaso.parsers.sqlite_plugins import chrome_cookies

from tests.parsers.sqlite_plugins import test_lib


class Chrome17CookiesPluginTest(test_lib.SQLitePluginTestCase):
  """Tests for the Google Chrome 17-65 cookie database plugin."""

  def testProcess(self):
    """Tests the Process function on a Chrome cookie database file."""
    plugin = chrome_cookies.Chrome17CookiePlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(['cookies.db'], plugin)

    # 560 Chrome cookie and 43 cookie plugin.
    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 603)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'access_time': '2011-08-25T21:50:27.292367+00:00',
        'creation_time': '2011-08-25T21:48:20.792703+00:00',
        'cookie_name': 'leo_auth_token',
        'data': (
            '"LIM:137381921:a:21600:1314308846:'
            '8797616454cd88b46baad44abb3c29ac45e467d7"'),
        'data_type': 'chrome:cookie:entry',
<<<<<<< HEAD
        'date_time': '2011-08-25T21:50:27.292367+00:00',
=======
        'expiration_time': '2011-11-23T21:48:19.792703+00:00',
>>>>>>> origin/main
        'host': 'www.linkedin.com',
        'httponly': False,
        'persistent': True,
        'url': 'http://www.linkedin.com/'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[124], expected_event_values)

    # Check one of the visits to rubiconproject.com.
    expected_event_values = {
        'cookie_name': 'put_2249',
        'data_type': 'chrome:cookie:entry',
        'date_time': '2012-04-01T13:54:34.949210+00:00',
        'httponly': False,
        'path': '/',
        'persistent': True,
        'secure': False,
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS,
        'url': 'http://rubiconproject.com/'}

    self.CheckEventValues(storage_writer, events[379], expected_event_values)

    # Examine an event for a visit to a political blog site.
    expected_event_values = {
        'data_type': 'chrome:cookie:entry',
        'date_time': '2012-03-22T01:47:21.012022+00:00',
        'host': 'politicalticker.blogs.cnn.com',
        'path': '/2012/03/21/romney-tries-to-clean-up-etch-a-sketch-mess/'}

    self.CheckEventValues(storage_writer, events[444], expected_event_values)

    # Examine a cookie that has an autologin entry.
    # This particular cookie value represents a timeout value that
    # corresponds to the expiration date of the cookie.
    expected_event_values = {
        'cookie_name': 'autologin[timeout]',
        'data': '1364824322',
        'data_type': 'chrome:cookie:entry',
        'date_time': '2012-04-01T13:52:56.189444+00:00',
        'host': 'marvel.com',
        'timestamp_desc': definitions.TIME_DESCRIPTION_CREATION}

    self.CheckEventValues(storage_writer, events[1425], expected_event_values)

    # Examine a cookie expiry event.
    expected_event_values = {
        'data_type': 'chrome:cookie:entry',
        'date_time': '2013-08-14T14:19:42.000000+00:00',
        'timestamp_desc': definitions.TIME_DESCRIPTION_EXPIRATION}

    self.CheckEventValues(storage_writer, events[2], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 45)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


class Chrome66CookiesPluginTest(test_lib.SQLitePluginTestCase):
  """Tests for the Google Chrome 66 Cookies database plugin."""

  def testProcess(self):
    """Tests the Process function on a Chrome cookie database file."""
    plugin = chrome_cookies.Chrome66CookiePlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['Cookies-68.0.3440.106'], plugin)

    # 5 Chrome cookie and 1 cookie plugin.
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
        'access_time': '2018-08-14T15:03:45.489599+00:00',
        'cookie_name': '__utma',
        'creation_time': '2018-08-14T15:03:43.650324+00:00',
        'data': '',
        'data_type': 'chrome:cookie:entry',
<<<<<<< HEAD
        'date_time': '2018-08-14T15:03:43.650324+00:00',
=======
        'expiration_time': '2020-08-13T15:03:45.000000+00:00',
>>>>>>> origin/main
        'host': 'google.com',
        'httponly': False,
        'persistent': True,
        'url': 'http://google.com/gmail/about/'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
<<<<<<< HEAD
        'cookie_name': '__cfduid',
        'data_type': 'chrome:cookie:entry',
        'date_time': '2018-08-20T17:19:53.134291+00:00',
        'httponly': True,
        'path': '/',
        'persistent': True,
        'secure': False,
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_ACCESS,
        'url': 'http://fbi.gov/'}

    self.CheckEventValues(storage_writer, events[10], expected_event_values)

    # Examine an event for a cookie with a very large expire time.
    expected_event_values = {
        'data_type': 'chrome:cookie:entry',
        'date_time': '9999-08-17T12:26:28.000000+00:00',
        'host': 'projects.fivethirtyeight.com'}

    self.CheckEventValues(storage_writer, events[8], expected_event_values)
=======
        'cookie_name': '__utma',
        'data_type': 'cookie:google:analytics:utma',
        'url': 'http://google.com/gmail/about/'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 1)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
