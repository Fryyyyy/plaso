# -*- coding: utf-8 -*-
"""Mac Core Location services helper."""

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
