# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) Oversize formatter helper."""

from plaso.lib import errors
from plaso.parsers import logger

class FormatterFlags(object):
  """Helper class for message formatter flags."""

  def __init__(self):
    """Initialises a FormatterFlags object."""
    self.absolute = False
    self.data_ref_id = 0
    self.large_offset_data = 0
    self.large_shared_cache = 0
    self.offset = 0
    self.shared_cache = False
    self.uuid_file_index = -1
    self.uuid_relative = False

class FormatterFlagsHelper():
  """Helper class to process common formatting flags."""

  # Flag constants
  _FLAG_CHECK = 0xe

  # Offset to format string is larger than normal
  _HAS_LARGE_OFFSET = 0x20
  _HAS_LARGE_SHARED_CACHE = 0xc
  # The log uses an alternative index number that points to the UUID
  # file name in the Catalog which contains the format string
  _HAS_ABSOLUTE = 0x8
  # A UUID file contains the format string (main_exe)
  _HAS_FMT_IN_UUID = 0x2
  # DSC file contains the format string
  _HAS_SHARED_CACHE = 0x4
  # The UUID file name is in the log data (instead of the Catalog)
  _HAS_UUID_RELATIVE = 0xa

  def FormatFlags(self, tracev3, flags, data, offset):
    """Check the log line's flags and consume appropriate variables.

    Args:
      flags (int): Flags bitfield.
      data (bytes): The raw message data.
      offset (int): The starting offset into the data.

    Returns:
      FormatterFlags() object.

    Raises:
      ParseError: if the flags cannot be parsed.
    """
    ret = FormatterFlags()
    uint16_data_type_map = tracev3._GetDataTypeMap('uint16')

    if flags & self._FLAG_CHECK == self._HAS_LARGE_OFFSET:
      ret.large_offset_data = tracev3._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.info('Has large offset: {0:d}'.format(ret.large_offset_data))
      if flags & self._HAS_LARGE_SHARED_CACHE:
        ret.large_shared_cache = tracev3._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.info(
          'Has large shared cache: {0:d}'.format(ret.large_shared_cache))
    elif flags & self._FLAG_CHECK == self._HAS_LARGE_SHARED_CACHE:
      if flags & self._HAS_LARGE_OFFSET:
        ret.large_offset_data = tracev3._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.info('Has large offset: {0:d}'.format(ret.large_offset_data))
      ret.large_shared_cache = tracev3._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.info(
        'Has large shared cache: {0:d}'.format(ret.large_shared_cache))
    elif flags & self._FLAG_CHECK == self._HAS_ABSOLUTE:
      logger.info('Absolute')
      ret.absolute = True
      if flags & self._HAS_FMT_IN_UUID == 0:
        logger.info('Alt index')
        ret.uuid_file_index = tracev3._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
    elif flags & self._FLAG_CHECK == self._HAS_FMT_IN_UUID:
      logger.info('main_exe')
    elif flags & self._FLAG_CHECK == self._HAS_SHARED_CACHE:
      logger.info('shared_cache')
      ret.shared_cache = True
      if flags & self._HAS_LARGE_OFFSET:
        ret.large_offset_data = tracev3._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.info('Has large offset: {0:d}'.format(ret.large_offset_data))
    elif flags & self._FLAG_CHECK == self._HAS_UUID_RELATIVE:
      ret.uuid_relative = tracev3._ReadStructureFromByteStream(
          data[offset:], offset, tracev3._GetDataTypeMap('uuid_be'))
      offset += 16
      logger.info('uuid_relative: {0:s}'.format(ret.uuid_relative.hex))
    else:
      raise errors.ParseError('Unknown formatter flag')

    ret.offset = offset
    return ret
