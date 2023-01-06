# -*- coding: utf-8 -*-
"""Text parser plugin for vsftpd log files."""

import pyparsing

from dfdatetime import time_elements as dfdatetime_time_elements

from plaso.containers import events
from plaso.lib import errors
from plaso.parsers import text_parser
from plaso.parsers.text_plugins import interface


class VsftpdLogEventData(events.EventData):
  """vsftpd log event data.

  Attributes:
    added_time (dfdatetime.DateTimeValues): date and time the log entry
        was added.
    text (str): vsftpd log message.
  """

  DATA_TYPE = 'vsftpd:log'

  def __init__(self):
    """Initializes event data."""
    super(VsftpdLogEventData, self).__init__(data_type=self.DATA_TYPE)
    self.added_time = None
    self.text = None


class VsftpdLogTextPlugin(interface.TextPlugin):
  """Text parser plugin for vsftpd log files."""

  NAME = 'vsftpd'
  DATA_FORMAT = 'vsftpd log file'

  _MONTH_DICT = {
      'jan': 1,
      'feb': 2,
      'mar': 3,
      'apr': 4,
      'may': 5,
      'jun': 6,
      'jul': 7,
      'aug': 8,
      'sep': 9,
      'oct': 10,
      'nov': 11,
      'dec': 12}

  _ONE_OR_TWO_DIGITS = pyparsing.Word(pyparsing.nums, max=2).setParseAction(
      lambda tokens: int(tokens[0], 10))

  _TWO_DIGITS = pyparsing.Word(pyparsing.nums, exact=2).setParseAction(
      lambda tokens: int(tokens[0], 10))

  _FOUR_DIGITS = pyparsing.Word(pyparsing.nums, exact=4).setParseAction(
      lambda tokens: int(tokens[0], 10))

  _THREE_LETTERS = pyparsing.Word(pyparsing.alphas, exact=3)

  # Date and time values are formatted as: Mon Jun  6 18:43:28 2016
  _DATE_TIME = pyparsing.Group(
      _THREE_LETTERS + _THREE_LETTERS + _ONE_OR_TWO_DIGITS +
      _TWO_DIGITS + pyparsing.Suppress(':') +
      _TWO_DIGITS + pyparsing.Suppress(':') + _TWO_DIGITS +
      _FOUR_DIGITS)

  _END_OF_LINE = pyparsing.Suppress(pyparsing.LineEnd())

  _LOG_LINE = (
      _DATE_TIME.setResultsName('date_time') +
      pyparsing.restOfLine().setResultsName('text') +
      _END_OF_LINE)

  _LINE_STRUCTURES = [('log_line', _LOG_LINE)]

<<<<<<< HEAD
  _SUPPORTED_KEYS = frozenset([key for key, _ in _LINE_STRUCTURES])

  def _GetTimeElementsTuple(self, structure):
    """Retrieves a time elements tuple from the structure.

    Args:
      structure (pyparsing.ParseResults): structure of tokens derived from
          a line of a vsftp log file.

    Returns:
      tuple: containing:
        year (int): year.
        month (int): month, where 1 represents January.
        day_of_month (int): day of month, where 1 is the first day of the month.
        hours (int): hours.
        minutes (int): minutes.
        seconds (int): seconds.
    """
    time_elements_tuple = self._GetValueFromStructure(structure, 'date_time')
    _, month, day_of_month, hours, minutes, seconds, year = time_elements_tuple
    month = self._MONTH_DICT.get(month.lower(), 0)
    return year, month, day_of_month, hours, minutes, seconds

  def _ParseLogLine(self, parser_mediator, structure):
    """Parses a log line.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      structure (pyparsing.ParseResults): structure of tokens derived from
          a line of a text file.
    """
    try:
      time_elements_tuple = self._GetTimeElementsTuple(structure)
      date_time = dfdatetime_time_elements.TimeElements(
          time_elements_tuple=time_elements_tuple)
      date_time.is_local_time = True
    except (TypeError, ValueError):
      parser_mediator.ProduceExtractionWarning('invalid date time value')
      return

    event_data = VsftpdEventData()
    event_data.text = self._GetValueFromStructure(structure, 'text')

    event = time_events.DateTimeValuesEvent(
        date_time, definitions.TIME_DESCRIPTION_ADDED,
        time_zone=parser_mediator.timezone)
    parser_mediator.ProduceEventWithEventData(event, event_data)
=======
  VERIFICATION_GRAMMAR = _LOG_LINE
>>>>>>> origin/main

  def _ParseRecord(self, parser_mediator, key, structure):
    """Parses a pyparsing structure.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      key (str): name of the parsed structure.
      structure (pyparsing.ParseResults): tokens from a parsed log line.

    Raises:
      ParseError: if the structure cannot be parsed.
    """
    time_elements_structure = self._GetValueFromStructure(
        structure, 'date_time')

    event_data = VsftpdLogEventData()
    event_data.added_time = self._ParseTimeElements(time_elements_structure)
    # TODO: extract pid and username.
    event_data.text = self._GetStringValueFromStructure(structure, 'text')

    parser_mediator.ProduceEventData(event_data)

  def _ParseTimeElements(self, time_elements_structure):
    """Parses date and time elements of a log line.

    Args:
      time_elements_structure (pyparsing.ParseResults): date and time elements
          of a log line.

    Returns:
      dfdatetime.TimeElements: date and time value.

    Raises:
      ParseError: if a valid date and time value cannot be derived from
          the time elements.
    """
    try:
      _, month_string, day_of_month, hours, minutes, seconds, year = (
          time_elements_structure)

      month = self._MONTH_DICT.get(month_string.lower(), 0)

      time_elements_tuple = (year, month, day_of_month, hours, minutes, seconds)
      date_time = dfdatetime_time_elements.TimeElements(
          time_elements_tuple=time_elements_tuple)
      date_time.is_local_time = True

      return date_time

    except (TypeError, ValueError) as exception:
      raise errors.ParseError(
          'Unable to parse time elements with error: {0!s}'.format(exception))

  def CheckRequiredFormat(self, parser_mediator, text_reader):
    """Check if the log record has the minimal structure required by the plugin.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfVFS.
      text_reader (EncodedTextReader): text reader.

    Returns:
      bool: True if this is the correct parser, False otherwise.
    """
    try:
      structure = self._VerifyString(text_reader.lines)
    except errors.ParseError:
      return False

    time_elements_structure = self._GetValueFromStructure(
        structure, 'date_time')

    try:
<<<<<<< HEAD
      parsed_structure = self._LOG_LINE.parseString(line)
    except pyparsing.ParseException:
      return False

    try:
      time_elements_tuple = self._GetTimeElementsTuple(parsed_structure)
      dfdatetime_time_elements.TimeElements(
          time_elements_tuple=time_elements_tuple)
    except (TypeError, ValueError):
=======
      self._ParseTimeElements(time_elements_structure)
    except errors.ParseError:
>>>>>>> origin/main
      return False

    return True


text_parser.TextLogParser.RegisterPlugin(VsftpdLogTextPlugin)
