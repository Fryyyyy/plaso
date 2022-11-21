# -*- coding: utf-8 -*-
"""Mac Core Location services helper."""
import os

from plaso.lib import dtfabric_helper
from plaso.lib import errors

class ClientAuthStatusHelper(object):
  """Core Location Client Authorisation Status helper"""
  _AUTH_STATUS_CODES = {
    0: 'Not Determined',
    1: 'Restricted',
    2: 'Denied',
    3: 'Authorized Always',
    4: 'Authorized When In Use'}

  @classmethod
  def GetCode(cls, code):
    """Retrieves the description for a code.

    Args:
      code (int): status code

    Returns:
      str: name of the status code or None if not available.
    """
    return cls._AUTH_STATUS_CODES.get(code, str(code))

class DaemonStatusHelper(object):
  """Core Location Daemon Status helper"""
  _DAEMON_STATUS_CODES = {
    0: 'Reachability Unavailable',
    1: 'Reachability Small',
    2: 'Reachability Large',
    56: 'Reachability Unachievable'}

  @classmethod
  def GetCode(cls, code):
    """Retrieves the description for a code.

    Args:
      code (int): status code

    Returns:
      str: name of the status code or None if not available.
    """
    return cls._DAEMON_STATUS_CODES.get(code, str(code))

class SubharvesterIDelper(object):
  """Core Location Subharvster ID helper"""
  _SUBHARVESTER_ID = {
    1: 'Wifi',
    2: 'Tracks',
    3: 'Realtime',
    4: 'App',
    5: 'Pass',
    6: 'Indoor',
    7: 'Pressure',
    8: 'Poi',
    9: 'Trace',
    10: 'Avenger',
    11: 'Altimeter',
    12: 'Ionosphere',
    13: 'Unknown'}

  @classmethod
  def GetCode(cls, id):
    """Retrieves the description for an ID.

    Args:
      id (int): identifier

    Returns:
      str: name of the ID or None if not available.
    """
    return cls._SUBHARVESTER_ID.get(id, str(id))


class LocationManagerStateTrackerParser(dtfabric_helper.DtFabricHelper):
  """LocationManagerStateTracker data chunk parser"""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'location.yaml')

  def Parse(self, size, data):
    """Parses given data of a given size as a LocationManagerStateTracker chunk

    Args:
      size (int):  Size of the parsed data
      data (bytes): Raw data

    Returns:
      tuple(Dict, Dict): The state tracker data and an optional extra structure
        if running on Catalina.

    Raises:
      ParseError: if the data cannot be parsed.
    """
    state_tracker_structure = {}
    extra_state_tracker_structure = {}

    if size not in [64, 72]:
      raise errors.ParseError(
        "Possibly corrupted CLLocationManagerStateTracker block")
    state_tracker_structure = self._ReadStructureFromByteStream(
        data, 0, self._GetDataTypeMap(
          'location_manager_state_data')).__dict__
    if len(data) == 72:
      extra_state_tracker_structure = self._ReadStructureFromByteStream(
          data[64:], 64, self._GetDataTypeMap(
            'location_manager_state_data_extra')).__dict__

    return (state_tracker_structure, extra_state_tracker_structure)
