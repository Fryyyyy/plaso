# pylint: disable=line-too-long
# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) file parser."""

import csv
import decimal
import ipaddress
import os
import re

import lz4.block

from dfdatetime import apfs_time as dfdatetime_apfs_time
from dfdatetime import posix_time as dfdatetime_posix_time


from plaso.containers import events
from plaso.containers import time_events

from plaso.helpers.mac import dns
from plaso.helpers.mac import location
from plaso.helpers.mac import opendirectory
from plaso.helpers import sqlite

from plaso.lib.aul import dsc
from plaso.lib.aul import formatter
from plaso.lib.aul import oversize
from plaso.lib.aul import statedump
from plaso.lib.aul import time as aul_time
from plaso.lib.aul import timesync
from plaso.lib.aul import uuidfile

from plaso.lib import definitions as plaso_definitions
from plaso.lib import dtfabric_helper
from plaso.lib import errors
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import logger
from plaso.parsers import manager


class TraceV3FileParser(interface.FileObjectParser,
                        dtfabric_helper.DtFabricHelper):
  """Apple Unified Logging and Activity Tracing (tracev3) file."""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  _CATALOG_LZ4_COMPRESSION = 0x100

  # Chunk Tags
  _CHUNK_TAG_HEADER = 0x1000
  _CHUNK_TAG_FIREHOSE = 0x6001
  _CHUNK_TAG_OVERSIZE = 0x6002
  _CHUNK_TAG_STATEDUMP = 0x6003
  _CHUNK_TAG_CATALOG = 0x600B
  _CHUNK_TAG_CHUNKSET = 0x600D

  # Statedump Types
  STATETYPE_PLIST = 0x1
  STATETYPE_PROTOBUF = 0x2
  STATETYPE_CUSTOM = 0x3

  # Activity Types
  _FIREHOSE_LOG_ACTIVITY_TYPE_ACTIVITY = 0x2
  _FIREHOSE_LOG_ACTIVITY_TYPE_TRACE = 0x3
  _FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY = 0x4
  _FIREHOSE_LOG_ACTIVITY_TYPE_SIGNPOST = 0x6
  _FIREHOSE_LOG_ACTIVITY_TYPE_LOSS = 0x7

  # Item Types
  FIREHOSE_ITEM_NUMBER_TYPES = [0x0, 0x2]
  FIREHOSE_ITEM_STRING_PRIVATE = 0x1
  FIREHOSE_ITEM_PRIVATE_STRING_TYPES = [
    0x21, 0x25, 0x31, 0x35, 0x41
  ]
  FIREHOSE_ITEM_STRING_TYPES = [
    0x20, 0x22, 0x30, 0x32, 0x40, 0x42, 0xf2
  ]
  FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES = [
    0x30, 0x31, 0x32
  ]
  FIREHOSE_ITEM_STRING_BASE64_TYPE = 0xf2
  FIREHOSE_ITEM_PRECISION_TYPES = [0x10, 0x12]
  FIREHOSE_ITEM_SENSITIVE = 0x45

  # Log Types
  _LOG_TYPES = {
    0x01: "Info",
    0x02: "Debug",
    0x03: "Useraction",
    0x10: "Error",
    0x11: "Fault",
    0x80: "Process Signpost Event",
    0x81: "Process Signpost Start",
    0x82: "Process Signpost End",
    0xc0: "System Signpost Event",
    0xc1: "System Signpost Start",
    0xc2: "System Signpost End",
    0x40: "Thread Signpost Event",
    0x41: "Thread Signpost Start",
    0x42: "Thread Signpost End",
  }

  # Flag constants
  CURRENT_AID = 0x1
  UNIQUE_PID = 0x10
  PRIVATE_STRING_RANGE = 0x100
  HAS_MESSAGE_IN_UUIDTEXT = 0x0002
  HAS_ALTERNATE_UUID = 0x0008
  HAS_SUBSYSTEM = 0x0200
  HAS_TTL = 0x0400
  HAS_DATA_REF = 0x0800
  HAS_CONTEXT_DATA = 0x1000
  HAS_SIGNPOST_NAME = 0x8000

  # Taken from https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/unified_log.rs#L203
  # format_strings_re = re.compile(r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))")
  format_strings_re = re.compile(r"%(\{[^\}]{1,64}\})?([0-9. *\-+#']{0,6})([hljztLq]{0,2})([@dDiuUxXoOfeEgGcCsSpaAFP])")

  def __init__(self, timesync_parser, uuid_parser, dsc_parser):
    """Initializes a tracev3 file parser.
    """
    super(TraceV3FileParser, self).__init__()
    self.boot_uuid_ts_list = None
    self.catalog = None
    self.catalog_files = []
    self.chunksets = []
    self.dsc_parser = dsc_parser
    self.header = None
    self.logs = []
    self.oversize_data = []
    self.timesync_parser = timesync_parser
    self.uuid_parser = uuid_parser

  def _FormatString(self, format_string, data):
    if len(format_string) == 0:
      if len(data) == 0:
        return ''
      return data[0][2]

    string_data_type_map = self._GetDataTypeMap('cstring')
    uuid_data_type_map = self._GetDataTypeMap('uuid_be')
    int8_data_type_map = self._GetDataTypeMap('char')
    uint8_data_type_map = self._GetDataTypeMap('uint8')
    int32_data_type_map = self._GetDataTypeMap('int32')
    uint32_data_type_map = self._GetDataTypeMap('uint32')
    float32_data_type_map = self._GetDataTypeMap('float32')
    int64_data_type_map = self._GetDataTypeMap('int64')
    uint64_data_type_map = self._GetDataTypeMap('uint64')
    float64_data_type_map = self._GetDataTypeMap('float64')

    # Set up for floating point
    ctx = decimal.Context()
    ctx.prec = 20

    output = ""
    i = 0
    last_start_index = 0
    for match in self.format_strings_re.finditer(format_string.replace("%%", "~~")):
      data_map = None

      output += format_string[last_start_index:match.start()].replace('%%', '%')
      last_start_index = match.end()
      if match.group().startswith("% "):
        continue

      if i >= len(data):
        output += "<decode: missing data>"
        continue

      data_item = data[i]

      custom_specifier = match.group(1) or ''
      # Done
      #  uuid_t          %{uuid_t}.16P            10742E39-0657-41F8-AB99-878C5EC2DCAA
      #  BOOL            %{BOOL}d                 YES
      #  bool            %{bool}d                 true
      #  sockaddr        %{network:sockaddr}.*P   fe80::f:86ff:fee9:5c16
      #  time_t          %{time_t}d               2016-01-12 19:41:37
      #TODO(fryy): Implement
    #  Value type      Custom specifier         Example output
    #  darwin.errno    %{darwin.errno}d         [32: Broken pipe]
    #  darwin.mode     %{darwin.mode}d          drwxr-xr-x
    #  darwin.signal   %{darwin.signal}d        [sigsegv: Segmentation Fault]
    #  timeval         %{timeval}.*P            2016-01-12 19:41:37.774236
    #  timespec        %{timespec}.*P           2016-01-12 19:41:37.2382382823
    #  bytes           %{bytes}d                4.72 kB
    #  iec-bytes       %{iec-bytes}d            4.61 KiB
    #  bitrate         %{bitrate}d              123 kbps
    #  iec-bitrate     %{iec-bitrate}d          118 Kibps
    #  in_addr         %{network:in_addr}d      127.0.0.1
    #  in6_addr        %{network:in6_addr}.16P  fe80::f:86ff:fee9:5c16

      #TODO(fryy): Remove
      if custom_specifier and 'signpost' not in custom_specifier and 'name' not in custom_specifier and custom_specifier not in [
        '{private, mask.hash, network:in_addr}', '{public,mdns:dnshdr}', '{private, mask.hash}', '{public, location:CLClientAuthorizationStatus}', '{odtypes:ODError}', '{odtypes:mbridtype}', '{PUBLIC}', '{public, name=transaction_seed}', '{public, location:SqliteResult}', '{public,network:sockaddr}', '{public,odtypes:nt_sid_t}', '{public,odtypes:mbr_details}', '{uuid_t}', '{public,uuid_t}', '{public, location:escape_only}', '{private, location:escape_only}', '{time_t}', '{bool}', '{BOOL}', '{public,BOOL}', '{public}', '{private}']:
        logger.warning("Custom specifier not supported: {}".format(custom_specifier))
      flags_width_precision = match.group(2).replace('\'', '')
      length_modifier = match.group(3)
      specifier = match.group(4)
      data_type = data_item[0]
      data_size = data_item[1]
      raw_data  = data_item[2]

      # Weird hack for "%{public}" which isn't a legal format string
      if flags_width_precision == ' ':
        last_start_index -= 2

      if 'mask.hash' in custom_specifier and data_type == 0xF2:
        pass # decoder.rs:50

      if (data_type in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES) and len(raw_data) == 0 and (data_size == 0 or (data_type == self.FIREHOSE_ITEM_STRING_PRIVATE and data_size == 0x8000)):
        output += "<private>"
        i += 1
        continue

      if (specifier not in ('p', 'P', 's', 'S')) and '*' in flags_width_precision:
        raise errors.ParseError("* not supported")

      if data_type in self.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES and specifier != 'P':
        raise errors.ParseError("Non-pointer Arbitrary type")

      if specifier in ('d', 'D', 'i', 'u', 'U', 'x', 'X', 'o', 'O'):
        number = 0
        if data_size == 0 and data_type != self.FIREHOSE_ITEM_STRING_PRIVATE:
          raise errors.ParseError("Size 0 in int fmt {0:s} // data {1!s}".format(format_string, data_item))
        elif data_type == self.FIREHOSE_ITEM_STRING_PRIVATE and not raw_data:
          output += "0" # A private number
        else:
          if specifier in ('d', 'D', 'i'):
            specifier = 'd'
            if data_size == 1:
              data_map = int8_data_type_map
            elif data_size == 4:
              data_map = int32_data_type_map
            elif data_size == 8:
              data_map = int64_data_type_map
            else:
              raise errors.ParseError("Unknown data_size for signed int: {0:d} // fmt {1:s}".format(data_size, format_string))
          else:
            if data_size == 1:
              data_map = uint8_data_type_map
            elif data_size == 4:
              data_map = uint32_data_type_map
            elif data_size == 8:
              data_map = uint64_data_type_map
            else:
              raise errors.ParseError("Unknown data_size for unsigned int: {0:d} // fmt {1:s}".format(data_size, format_string))
            if specifier in ('u', 'U'):
              specifier = 'd'
            elif specifier == 'O':
              specifier = 'o'
          width_and_precision = flags_width_precision.split(".")
          if len(width_and_precision) == 2:
            flags_width_precision = "0" + width_and_precision[0]
          if flags_width_precision.startswith("-"):
            flags_width_precision = '<' + flags_width_precision[1:]
          if flags_width_precision == ".":
            flags_width_precision = ".0"
          format_code = '{:' + flags_width_precision + specifier + '}'
          number = self._ReadStructureFromByteStream(raw_data, 0, data_map)
          #TODO(fryy): Delete
          try:
            if ('%' + flags_width_precision + specifier) % number != format_code.format(number):
              raise errors.ParseError("FRY FIX")
          except ValueError:
            pass
          if "BOOL" in custom_specifier:
            if bool(number):
              output += "YES"
            else:
              output += "NO"
          elif "bool" in custom_specifier:
            output += str(bool(number)).lower()
          elif "time_t" in custom_specifier:
            # Timestamp in seconds ?
            output += dfdatetime_posix_time.PosixTime(timestamp=number).CopyToDateTimeString()
          elif "odtypes:ODError" in custom_specifier:
            output += opendirectory.ODErrorsHelper.GetError(number)
          elif "odtypes:mbridtype" in custom_specifier:
            output += opendirectory.ODMBRIdHelper.GetType(number)
          elif 'location:CLClientAuthorizationStatus' in custom_specifier:
            output += location.ClientAuthStatusHelper.GetCode(number)
          else:
            output += format_code.format(number)
      elif specifier in ('f', 'e', 'E', 'g', 'G', 'a', 'A', 'F'):
        number = 0
        if data_size == 0 and data_type != self.FIREHOSE_ITEM_STRING_PRIVATE:
          raise errors.ParseError("Size 0 in float fmt {0:s} // data {1!s}".format(format_string, data_item))
        elif data_type == self.FIREHOSE_ITEM_STRING_PRIVATE and not raw_data:
          output += '0' # A private number
        else:
          if data_size == 4:
            data_map = float32_data_type_map
          elif data_size == 8:
            data_map = float64_data_type_map
          else:
            raise errors.ParseError("Unknown data_size for float int: {0:d} // fmt {1:s}".format(data_size, format_string))
          try:
            number = self._ReadStructureFromByteStream(raw_data, 0, data_map)
          except ValueError:
            pass
          if flags_width_precision:
            if flags_width_precision == ".":
              flags_width_precision = ".0"
            format_code = '{:' + flags_width_precision + specifier + '}'
            try:
              output += format_code.format(number)
            except ValueError:
              pass
          else:
            output += format(ctx.create_decimal(repr(number)), 'f')
      elif specifier in ('c', 'C', 's', 'S', '@'):
        specifier = 's'
        chars = ''
        if data_size == 0:
          if data_type in self.FIREHOSE_ITEM_STRING_TYPES:
            chars = '(null)'
          elif data_type & self.FIREHOSE_ITEM_STRING_PRIVATE:
            chars = '<private>'
        else:
          chars = raw_data
          if isinstance(chars, bytes):
            chars = chars.decode('utf-8').rstrip('\x00')
          if "*" in flags_width_precision:
            flags_width_precision = ''
          old = ('%' + flags_width_precision + specifier) % chars
          if flags_width_precision.isdigit():
            flags_width_precision = ">" + flags_width_precision
          format_code = '{:' + flags_width_precision + specifier + '}'
          try:
            if old != format_code.format(chars):
              raise errors.ParseError("FRY FIX")
          except ValueError:
            pass
          except TypeError:
            pass
          chars = format_code.format(chars)
        output += chars
      elif specifier == 'P':
        if not custom_specifier:
          raise errors.ParseError("Pointer with no custom specifier")
        if data_size == 0:
          continue
        if "uuid_t" in custom_specifier:
          if data_type in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES and not raw_data:
            chars = "<private>"
          else:
            uuid = self._ReadStructureFromByteStream(raw_data, 0, uuid_data_type_map)
            chars = str(uuid).upper()
        elif "odtypes:mbr_details" in custom_specifier:
          if raw_data[0] == 0x44 or raw_data[0] == 0x24: # Group or Alias(?)
            group_type = self._ReadStructureFromByteStream(raw_data[1:], 1, self._GetDataTypeMap('mbr_group_type'))
            mbr_type = "group"
            if raw_data[0] == 0x24:
              mbr_type = "user"
            chars = "{0:s}: {1:s}@{2:s}".format(mbr_type, group_type.name, group_type.domain)
          elif raw_data[0] == 0x23: # User
            uid = self._ReadStructureFromByteStream(raw_data[1:], 1, uint32_data_type_map)
            domain = self._ReadStructureFromByteStream(raw_data[5:], 5, string_data_type_map)
            chars = "user: {0:s}@{1:s}".format(uid, domain)
          else:
            raise errors.ParseError("Unknown MBR Details Header Byte: 0x{0:X}".format(raw_data[0]))
        elif "odtypes:nt_sid_t" in custom_specifier:
          sid = self._ReadStructureFromByteStream(raw_data, 1, self._GetDataTypeMap('nt_sid'))
          chars = 'S-{0:d}-{1:d}-{2:s}'.format(sid.rev, sid.authority, '-'.join([str(sa) for sa in sid.sub_authorities]))
        elif "network:sockaddr" in custom_specifier:
          sockaddr = self._ReadStructureFromByteStream(raw_data, 1, self._GetDataTypeMap('sockaddr'))
          # IPv6
          if sockaddr.family == 0x1E:
            if raw_data[8:24] == b'\x00'*16:
              chars = "IN6ADDR_ANY"
            else:
              chars = ipaddress.ip_address(self._FormatPackedIPv6Address(sockaddr.ipv6_ip.segments)).compressed
          # IPv4
          elif sockaddr.family == 0x02:
            chars = self._FormatPackedIPv4Address(sockaddr.ipv4_address.segments)
            if sockaddr.ipv4_port:
              chars += ":{0:d}".format(sockaddr.ipv4_port)
          else:
            raise errors.ParseError('Unknown Sockaddr Family')
        elif 'network:in_addr' in custom_specifier:
          ip_addr = self._ReadStructureFromByteStream(raw_data, 0, self._GetDataTypeMap('ipv4_address'))
          chars = self._FormatPackedIPv4Address(ip_addr.segments)
        elif 'network:in6_addr' in custom_specifier:
          ip_addr = self._ReadStructureFromByteStream(raw_data, 0, self._GetDataTypeMap('ipv6_address'))
          chars = ipaddress.ip_address(self._FormatPackedIPv4Address(ip_addr.segments)).compressed
        elif "location:SqliteResult" in custom_specifier:
          code = sqlite.SQLiteResultCodeHelper.GetResult(self._ReadStructureFromByteStream(raw_data, 0, uint32_data_type_map))
          if code:
            chars += '"{0:s}"'.format(code)
          else:
            raise errors.ParseError("Unknown SQLite Code")
        elif 'mdnsresponder:domain_name' in custom_specifier:
          chars = ''.join(['.' if not chr(s).isprintable() else chr(s) for s in raw_data.replace(b'\n', b'').replace(b'\t', b'').replace(b'\r', b'')])
        elif 'mdns:dnshdr' in custom_specifier:
          # ID = 28454
          # Recursion desired
          dnsheader = self._ReadStructureFromByteStream(raw_data, 0, self._GetDataTypeMap('dns_header'))
          flag_string = dns.DNSFlags.ParseFlags(dnsheader.flags)
          chars = "id: {0:s} ({1:d}), flags: 0x{2:04x} ({3:s}), counts: {4:d}/{5:d}/{6:d}/{7:d}".format(hex(dnsheader.id), dnsheader.id, dnsheader.flags, flag_string, dnsheader.questions, dnsheader.answers, dnsheader.authority_records, dnsheader.additional_records)
        else:
          raise errors.ParseError("Unknown data specifier: {}".format(custom_specifier))
        output += chars
      elif specifier == 'p':
        if data_size == 0:
          if data_type & self.FIREHOSE_ITEM_STRING_PRIVATE:
            output += '<private>'
          else:
            raise errors.ParseError("Size 0 in pointer fmt {0:s} // data {1!s}".format(format_string, data_item))
        else:
          if data_size == 4:
            data_map = uint32_data_type_map
          elif data_size == 8:
            data_map = uint64_data_type_map
          else:
            raise errors.ParseError("Unknown data_size for pointer: {0:d} // fmt {1:s}".format(data_size, format_string))
          try:
            number = self._ReadStructureFromByteStream(raw_data, 0, data_map)
          except ValueError:
            pass
          if flags_width_precision:
            raise errors.ParseError("Fry look at this, how to fix")
          #TODO(fryy): Revert
          output += (hex(number))[2:].upper()
      else:
        raise errors.ParseError("UNKNOWN SPECIFIER")

      i += 1

    if last_start_index < len(format_string):
      output += format_string[last_start_index:].replace('%%', '%')

    return output


  def _ReadHeader(self, file_object, file_offset):
    """Reads a Header.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the catalog data relative to the start
          of the file.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_header')

    self.header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    logger.info('Header data: CT {0:d} // Bias {1:d}'.format(self.header.continuous_time, self.header.bias_in_minutes))
    logger.info('SI Info: BVS: {0:s} // HMS: {1:s}'.format(self.header.systeminfo_subchunk.systeminfo_subchunk_data.build_version_string, self.header.systeminfo_subchunk.systeminfo_subchunk_data.hardware_model_string))
    logger.info('Boot UUID: {0:s}'.format(self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex))
    logger.info('TZ Info: {0:s}'.format(self.header.timezone_subchunk.timezone_subchunk_data.path_to_tzfile))

    self.boot_uuid_ts_list = aul_time.GetBootUuidTimeSyncList(
        self.timesync_parser.records, self.header.generation_subchunk.generation_subchunk_data.boot_uuid)
    logger.info('Tracev3 Header Timestamp: %s', aul_time.TimestampFromContTime(
          self.boot_uuid_ts_list.sync_records, self.header.continuous_time_subchunk.continuous_time_data))

  def _ReadCatalog(self, parser_mediator, file_object, file_offset):
    """Reads a catalog.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the catalog data relative to the start
          of the file.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_catalog')

    catalog, offset_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    logger.info("Catalog data: NumProcs {0:d} // NumSubChunks {1:d} // EarliestFirehoseTS {2:d}".format(catalog.number_of_process_information_entries, catalog.number_of_sub_chunks, catalog.earliest_firehose_timestamp))
    logger.info("Num UUIDS: {0:d} // Num SubSystemStrings {1:d}".format(len(catalog.uuids), len(catalog.sub_system_strings)))

    catalog.files = []

    for uuid in catalog.uuids:
      found = None
      found_in_cache = False
      filename = uuid.hex.upper()
      logger.info("Encountered UUID {0:s} in Catalog.".format(filename))
      for file in self.catalog_files:
        if file.uuid == filename:
          found = file
          found_in_cache = True
          logger.info("Found in cache")
          break
      if not found:
        found = self.dsc_parser.FindFile(parser_mediator, filename)
      if not found:
        found = self.uuid_parser.FindFile(parser_mediator, filename)
        if not found:
          raise errors.ParseError('Neither UUID nor DSC file found for UUID: {0:s}'.format(uuid.hex))
        else:
          if not found_in_cache:
            self.catalog_files.append(found)
          catalog.files.append(found)
      else:
        if not found_in_cache:
          self.catalog_files.append(found)
        catalog.files.append(found)

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_process_information_entry')
    catalog.process_entries = []

    for _ in range(catalog.number_of_process_information_entries):
      process_entry, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      try:
        process_entry.main_uuid = catalog.uuids[process_entry.main_uuid_index]
      except IndexError:
        pass
      try:
        process_entry.dsc_uuid = catalog.uuids[process_entry.catalog_dsc_index]
      except IndexError:
        pass
      process_entry.items = {}
      logger.info("Process Entry data: PID {0:d} // EUID {1:d}".format(process_entry.pid, process_entry.euid))
      for subsystem in process_entry.subsystems:
        offset = 0
        subsystem_string = None
        category_string = None
        for string in catalog.sub_system_strings:
          if subsystem_string is None:
            if offset >= subsystem.subsystem_offset:
              subsystem_string = string
          if category_string is None:
            if offset >= subsystem.category_offset:
              category_string = string
          offset += len(string) + 1
        process_entry.items[subsystem.identifier] = (subsystem_string, category_string)
        logger.info("Process Entry coalesce: Subsystem {0:s} // Category {1:s}".format(subsystem_string, category_string))
      catalog.process_entries.append(process_entry)
      offset_bytes += new_bytes

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_subchunk')
    catalog.subchunks = []

    for _ in range(catalog.number_of_sub_chunks):
      subchunk, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      logger.info("Catalog Subchunk data: Size {0:d}".format(subchunk.uncompressed_size))
      catalog.subchunks.append(subchunk)
      offset_bytes += new_bytes

    return catalog

  def _ReadChunkHeader(self, file_object, file_offset):
    """Reads a chunk header.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk header relative to the start
          of the file.

    Returns:
      tracev3_chunk_header: a chunk header.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_chunk_header')

    chunk_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    return chunk_header

  def _ReadChunkSet(self, parser_mediator, file_object, file_offset, chunk_header,
                        chunkset_index):
    """Reads a chunk set.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk set data relative to the start
          of the file.
      chunk_header (tracev3_chunk_header): the chunk header of the chunk set.
      chunkset_index (int): What number chunk this is in the catalog.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    if self.catalog.subchunks[
            chunkset_index].compression_algorithm != self._CATALOG_LZ4_COMPRESSION:
      raise errors.ParseError(
        "Unknown compression algorithm : {0:s}".format(self.catalog.compression_algorithm))

    chunk_data = file_object.read(chunk_header.chunk_data_size)

    data_type_map = self._GetDataTypeMap('tracev3_lz4_block_header')

    lz4_block_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)
    logger.info("Read LZ4 block: Compressed size {0:d} // Uncompressed size {1:d}".format(lz4_block_header.compressed_data_size, lz4_block_header.uncompressed_data_size))

    end_of_compressed_data_offset = 12 + lz4_block_header.compressed_data_size

    if lz4_block_header.signature == b'bv41':
      uncompressed_data = lz4.block.decompress(
          chunk_data[12:end_of_compressed_data_offset],
          uncompressed_size=lz4_block_header.uncompressed_data_size)

    elif lz4_block_header.signature == b'bv4-':
      logger.info("It was already uncompressed!")
      uncompressed_data = chunk_data[12:end_of_compressed_data_offset]

    else:
      raise errors.ParseError('Unsupported start of compressed data marker')

    end_of_compressed_data_identifier = chunk_data[
        end_of_compressed_data_offset:end_of_compressed_data_offset + 4]

    if end_of_compressed_data_identifier != b'bv4$':
      raise errors.ParseError('Unsupported end of compressed data marker')

    data_type_map = self._GetDataTypeMap('tracev3_chunk_header')

    data_offset = 0
    while data_offset < lz4_block_header.uncompressed_data_size:
      chunkset_chunk_header = self._ReadStructureFromByteStream(
          uncompressed_data[data_offset:], data_offset, data_type_map)
      data_offset += 16
      logger.info("Reading Decompressed Chunk: Size {0:d}".format(chunkset_chunk_header.chunk_data_size))

      data_end_offset = data_offset + chunkset_chunk_header.chunk_data_size
      chunkset_chunk_data = uncompressed_data[data_offset:data_end_offset]

      if chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_FIREHOSE:
        logger.info("Processing a Firehose Chunk (0x6001)")
        self._ReadFirehoseChunkData(
            parser_mediator, chunkset_chunk_data, data_offset)
      elif chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_OVERSIZE:
        logger.info("Processing an Oversize Chunk (0x6002)")
        op = oversize.OversizeParser()
        self.oversize_data.append(op.ReadOversizeChunkData(
          self, chunkset_chunk_data, data_offset))
      elif chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_STATEDUMP:
        logger.info("Processing an Statedump Chunk (0x6003)")
        sp = statedump.StatedumpParser()
        sp.ReadStatedumpChunkData(
          self, parser_mediator, chunkset_chunk_data, data_offset)
      else:
        raise errors.ParseError(
          "Unsupported Chunk Type: {0:d}".format(
            chunkset_chunk_header.chunk_tag))

      data_offset = data_end_offset

      _, alignment = divmod(data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      data_offset += alignment

  def _ParseSignpost(self, parser_mediator, tracepoint, proc_info, time, private_strings):
    logger.info("Parsing Signpost")

    log_data = []
    offset = 0
    data = tracepoint.data
    flags = tracepoint.flags

    data_ref_id = 0
    fmt = None
    private_string = None
    ttl_value = None

    event_data = AULEventData()
    event_data.boot_uuid = self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex

    try:
      dsc_file = self.catalog.files[proc_info.catalog_dsc_index]
    except IndexError:
      dsc_file = None

    try:
      uuid_file = self.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.uuid
      event_data.process = uuid_file.library_path
    except IndexError:
      uuid_file = None

    uint8_data_type_map = self._GetDataTypeMap('uint8')
    uint16_data_type_map = self._GetDataTypeMap('uint16')
    uint32_data_type_map = self._GetDataTypeMap('uint32')
    uint64_data_type_map = self._GetDataTypeMap('uint64')

    if flags & self.CURRENT_AID:
      logger.info("Signpost has current_aid")
      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4

    if flags & self.PRIVATE_STRING_RANGE:
      logger.info("Signpost has private_string_range (has_private_data flag)")

      private_strings_offset = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      private_strings_size = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2

    message_string_reference  = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.info("Unknown PCID: {0:d}".format(message_string_reference))

    ffh = formatter.FormatterFlagsHelper()
    formatter_flags = ffh.FormatFlags(self, flags, data, offset)
    offset = formatter_flags.offset

    subsystem_value = ''
    if flags & self.HAS_SUBSYSTEM:
      subsystem_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.info("Signpost has subsystem: {0:d}".format(subsystem_value))

    signpost_id = self._ReadStructureFromByteStream(
          data[offset:], offset, uint64_data_type_map)
    offset += 8

    if flags & self.HAS_TTL:
      ttl_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint8_data_type_map)
      offset += 1
      logger.info("Signpost has TTL: {0:d}".format(ttl_value))

    if flags & self.HAS_DATA_REF:
      data_ref_id = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 1
      logger.info("Signpost with data reference: {0:d}".format(data_ref_id))

    if flags & self.HAS_SIGNPOST_NAME:
      signpost_name = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4
      if formatter_flags.large_shared_cache != 0:
        offset += 2

    if flags & self.PRIVATE_STRING_RANGE:
      if private_strings:
        string_start = private_strings_offset - private_strings[0]
        if string_start > len(private_strings[1] or string_start < 0):
          raise errors.ParseError("Error with private string offset")
        private_string = private_strings[1][string_start:string_start + private_strings_size]
      else:
        raise errors.ParseError("Private strings wanted but not supplied")

    data_meta = self._ReadStructureFromByteStream(
      data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data'))
    offset += 2

    logger.info("After activity data: Unknown {0:d} // Number of Items {1:d}".format(data_meta.unknown1, data_meta.num_items))
    (log_data, deferred_data_items, offset) = self.ReadItems(data_meta, data, offset)

    if flags & self.HAS_CONTEXT_DATA != 0:
      raise errors.ParseError("Backtrace data in Signpost log chunk")

    for item in deferred_data_items:
      if item[2] == 0:
        result = ""
      elif item[0] in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES:
        if not private_string:
          raise errors.ParseError("Trying to read from empty Private String")
        try:
          result = self._ReadStructureFromByteStream(
            private_string[item[1]:], 0, self._GetDataTypeMap('cstring'))
        except errors.ParseError:
          result = '' # Private
      else:
        if item[0] in self.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
          result = data[offset + item[1]:offset + item[1] + item[2]]
        else:
          result = self._ReadStructureFromByteStream(
            data[offset + item[1]:], 0, self._GetDataTypeMap('cstring'))
          logger.info("End result: {0:s}".format(result))
        if item[0] == self.FIREHOSE_ITEM_STRING_BASE64_TYPE:
          raise errors.ParseError("Unsupported base64 type -- firehose_log.rs:797")
      log_data.insert(item[3], (item[0], item[2], result))

    found = False
    dsc_range = dsc.DSCRange()

    if data_ref_id != 0:
      for oversize_data in self.oversize_data:
        if oversize_data.first_proc_id == proc_info.first_number_proc_id and oversize_data.second_proc_id == proc_info.second_number_proc_id and oversize_data.data_ref_index == data_ref_id:
          log_data = oversize_data.strings
          found = True
          break
      if not found:
        logger.info("Did not find any oversize log entries from Data Ref ID: {0:d}, First Proc ID: {1:d}, and Second Proc ID: {2:d}".format(data_ref_id, proc_info.first_number_proc_id, proc_info.second_number_proc_id))

    if formatter_flags.shared_cache or formatter_flags.large_shared_cache != 0:
      if formatter_flags.large_offset_data != 0:
        raise errors.ParseError("Large offset Signpost not supported - signpost.rs:166")
      extra_offset_value_result = tracepoint.format_string_location
      (fmt, dsc_range) = self._ExtractSharedStrings(tracepoint.format_string_location, extra_offset_value_result, dsc_file)
    else:
      if formatter_flags.absolute:
        raise errors.ParseError("Absolute Signpost not supported - signpost.rs:224")
      elif formatter_flags.uuid_relative:
        uuid_file = self._ExtractAltUUID(formatter_flags.uuid_relative)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      else:
        fmt = self._ExtractFormatStrings(tracepoint.format_string_location, uuid_file)

    event_data.level = "Signpost"
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    event_data.thread_id = hex(tracepoint.thread_identifier)
    if ttl_value:
      event_data.ttl = ttl_value

    event_data.message = self._FormatString(fmt, log_data)
    if not event_data.message:
      return

    with open('/tmp/fryoutput.csv', 'a') as f:
      csv.writer(f).writerow([dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString(), event_data.level, event_data.message])

    event = time_events.DateTimeValuesEvent(dfdatetime_apfs_time.APFSTime(timestamp=time), plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)

  def _ParseActivity(self, parser_mediator, tracepoint, proc_info, time, private_strings):
    logger.info("Parsing activity")

    _USER_ACTION_ACTIVITY_TYPE = 0x3

    log_data = []
    offset = 0
    data = tracepoint.data
    flags = tracepoint.flags

    fmt = None
    private_string = None
    activity_id = None
    dsc_range = dsc.DSCRange()

    event_data = AULEventData()
    event_data.boot_uuid = self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex

    try:
      dsc_file = self.catalog.files[proc_info.catalog_dsc_index]
    except IndexError:
      dsc_file = None

    try:
      uuid_file = self.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.uuid
      event_data.process = uuid_file.library_path
    except IndexError:
      uuid_file = None

    uint32_data_type_map = self._GetDataTypeMap('uint32')
    uint64_data_type_map = self._GetDataTypeMap('uint64')

    if tracepoint.log_type != _USER_ACTION_ACTIVITY_TYPE:
      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4

    if flags & self.UNIQUE_PID:
      unique_pid = self._ReadStructureFromByteStream(
        data[offset:], offset, uint64_data_type_map)
      offset += 8
      logger.info("Signpost has unique_pid: {0:d}".format(unique_pid))

    if flags & self.CURRENT_AID:
      logger.info("Activity has current_aid")
      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4

    if flags & self.HAS_SUBSYSTEM:
      logger.info("Activity has has_other_current_aid")
      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4

    message_string_reference  = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.info("Unknown PCID: {0:d}".format(message_string_reference))

    ffh = formatter.FormatterFlagsHelper()
    formatter_flags = ffh.FormatFlags(self, flags, data, offset)
    offset = formatter_flags.offset

    if flags & self.PRIVATE_STRING_RANGE:
      raise errors.ParseError("Activity with Private String Range")

    # If there's data...
    if tracepoint.data_size - offset >= 6:
      data_meta = self._ReadStructureFromByteStream(
        data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data'))
      offset += 2

      logger.info("After activity data: Unknown {0:d} // Number of Items {1:d}".format(data_meta.unknown1, data_meta.num_items))
      (log_data, deferred_data_items, offset) = self.ReadItems(data_meta, data, offset)

      if flags & self.HAS_CONTEXT_DATA != 0:
        raise errors.ParseError("Backtrace data in Activity log chunk")

      if flags & self.HAS_DATA_REF:
        raise errors.ParseError("Activity log chunk with Data Ref")

      for item in deferred_data_items:
        if item[2] == 0:
          result = ""
        elif item[0] in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES:
          if not private_string:
            raise errors.ParseError("Trying to read from empty Private String")
          try:
            result = self._ReadStructureFromByteStream(
              private_string[item[1]:], 0, self._GetDataTypeMap('cstring'))
          except errors.ParseError:
            result = '' # Private
        else:
          if item[0] in self.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
            result = data[offset + item[1]:offset + item[1] + item[2]]
          else:
            result = self._ReadStructureFromByteStream(
              data[offset + item[1]:], 0, self._GetDataTypeMap('cstring'))
            logger.info("End result: {0:s}".format(result))
          if item[0] == self.FIREHOSE_ITEM_STRING_BASE64_TYPE:
            raise errors.ParseError("Unsupported base64 type -- firehose_log.rs:797")
        log_data.insert(item[3], (item[0], item[2], result))

    if formatter_flags.shared_cache or formatter_flags.large_shared_cache != 0:
      if formatter_flags.large_offset_data != 0:
        raise errors.ParseError("Large offset Activity not supported - activity.rs:140")
      extra_offset_value_result = tracepoint.format_string_location
      (fmt, dsc_range) = self._ExtractSharedStrings(tracepoint.format_string_location, extra_offset_value_result, dsc_file)
    else:
      if formatter_flags.absolute:
        raise errors.ParseError("Absolute Activity not supported - signpost.rs:224")
      elif formatter_flags.uuid_relative:
        uuid_file = self._ExtractAltUUID(formatter_flags.uuid_relative)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      else:
        fmt = self._ExtractFormatStrings(tracepoint.format_string_location, uuid_file)

    event_data.level = self._LOG_TYPES.get(tracepoint.log_type, "Default")

    # Info is 'Create' when it's an Activity
    if tracepoint.log_type == 0x1:
      event_data.level = "Create"

    if activity_id:
      event_data.activity_id = hex(activity_id)
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    event_data.thread_id = hex(tracepoint.thread_identifier)
    event_data.pid = proc_info.pid
    event_data.euid = proc_info.euid
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    event_data.message = self._FormatString(fmt, log_data)

    with open('/tmp/fryoutput.csv', 'a') as f:
      csv.writer(f).writerow([dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString(), event_data.level, event_data.message])

    event = time_events.DateTimeValuesEvent(dfdatetime_apfs_time.APFSTime(timestamp=time), plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)

  def _ParseNonActivity(self, parser_mediator, tracepoint, proc_info, time, private_strings):
    logger.info("Parsing non-activity")

    log_data = []
    offset = 0
    data = tracepoint.data
    flags = tracepoint.flags

    activity_id = None
    data_ref_id = 0
    fmt = None
    private_string = None
    ttl_value = None

    event_data = AULEventData()
    event_data.boot_uuid = self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex

    try:
      dsc_file = self.catalog.files[proc_info.catalog_dsc_index]
    except IndexError:
      dsc_file = None

    try:
      uuid_file = self.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.uuid
      event_data.process = uuid_file.library_path
    except IndexError:
      uuid_file = None

    _NON_ACTIVITY_SENINTEL = 0x80000000

    uint8_data_type_map = self._GetDataTypeMap('uint8')
    uint16_data_type_map = self._GetDataTypeMap('uint16')
    uint32_data_type_map = self._GetDataTypeMap('uint32')

    if flags & self.CURRENT_AID:
      logger.info("Non-activity has current_aid")

      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4
      if sentinel != _NON_ACTIVITY_SENINTEL:
        raise errors.ParseError("Incorrect sentinel value for Non-Activity")

    if flags & self.PRIVATE_STRING_RANGE:
      logger.info("Non-activity has private_string_range (has_private_data flag)")

      private_strings_offset = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      private_strings_size = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2

    message_string_reference  = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.info("Unknown PCID: {0:d}".format(message_string_reference))

    if flags & self.HAS_ALTERNATE_UUID:
      if flags & self.HAS_MESSAGE_IN_UUIDTEXT:
        logger.info("Non-activity: Has Alternate UUID & Message in UUIDText")
      else:
        logger.info("Non-activity: Has Alternate UUID & _NO_ Message in UUIDText")

    ffh = formatter.FormatterFlagsHelper()
    formatter_flags = ffh.FormatFlags(self, flags, data, offset)
    offset = formatter_flags.offset

    subsystem_value = ''
    if flags & self.HAS_SUBSYSTEM:
      subsystem_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.info("Non-activity has subsystem: {0:d}".format(subsystem_value))


    if flags & self.HAS_TTL:
      ttl_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint8_data_type_map)
      offset += 1
      logger.info("Non-activity has TTL: {0:d}".format(ttl_value))

    if flags & self.HAS_DATA_REF:
      data_ref_id = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 1
      logger.info("Non-activity with data reference: {0:d}".format(data_ref_id))

    if flags & self.HAS_SIGNPOST_NAME:
      raise errors.ParseError("Non-activity signpost not supported")

    if flags & self.HAS_MESSAGE_IN_UUIDTEXT:
      logger.info("Non-activity has message in UUID Text file")
      if flags & self.HAS_ALTERNATE_UUID and flags & self.HAS_SIGNPOST_NAME:
        raise errors.ParseError("Non-activity with Alternate UUID and Signpost not supported")
      else:
        if not uuid_file:
          raise errors.ParseError("Unable to continue without matching UUID file")
          return
        # fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
        if flags & self.HAS_SIGNPOST_NAME:
          raise errors.ParseError("Non-activity signpost not supported (2)")

    if flags & self.PRIVATE_STRING_RANGE:
      if private_strings:
        string_start = private_strings_offset - private_strings[0]
        if string_start > len(private_strings[1] or string_start < 0):
          raise errors.ParseError("Error with private string offset")
        private_string = private_strings[1][string_start:string_start + private_strings_size]
      else:
        raise errors.ParseError("Private strings wanted but not supplied")

    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")

    # TODO(fryy): Check for len(data[offset:] minimums)
    data_meta = self._ReadStructureFromByteStream(
      data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data'))
    offset += 2

    if len(data[offset:]) < 6:
      return

    logger.info("After activity data: Unknown {0:d} // Number of Items {1:d}".format(data_meta.unknown1, data_meta.num_items))
    (log_data, deferred_data_items, offset) = self.ReadItems(data_meta, data, offset)

    backtrace_strings = []
    if flags & self.HAS_CONTEXT_DATA != 0:
      logger.info("Backtrace data in Firehose log chunk")
      backtrace_strings = ["Backtrace:\n"]
      backtrace_data = self._ReadStructureFromByteStream(
        data[offset:], offset, self._GetDataTypeMap('tracev3_backtrace'))
      for count, idx in enumerate(backtrace_data.indices):
        try:
          #TODO(Fryy): Revert
          backtrace_strings.append("\"{0:s}\" +0x{1:d}\n".format(backtrace_data.uuids[idx].hex.upper(), backtrace_data.offsets[count]))
        except IndexError:
          pass
    elif len(data[offset:]) > 3:
      if data[offset:offset+3] == r"\x01\x00\x18":
        raise errors.ParseError("Backtrace signature without context -- firehose_logs.rs:330")

    #TODO(fryy): Turn item tuple into an object with names
    for item in deferred_data_items:
      if item[2] == 0:
        result = ""
      elif item[0] in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES:
        if not private_string:
          raise errors.ParseError("Trying to read from empty Private String")
        if item[0] in self.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
          result = private_string[item[1]:item[1] + item[2]]
        else:
          result = self._ReadStructureFromByteStream(
            private_string[item[1]:], 0, self._GetDataTypeMap('cstring'))
      elif item[0] == self.FIREHOSE_ITEM_STRING_PRIVATE:
        result = private_string[item[1]:item[1] + item[2]]
      else:
        if item[0] in self.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
          result = data[offset + item[1]:offset + item[1] + item[2]]
        else:
          result = self._ReadStructureFromByteStream(
            data[offset + item[1]:], 0, self._GetDataTypeMap('cstring'))
          logger.info("End result: {0:s}".format(result))
        if item[0] == self.FIREHOSE_ITEM_STRING_BASE64_TYPE:
          raise errors.ParseError("Unsupported base64 type -- firehose_log.rs:797")
      log_data.insert(item[3], (item[0], item[2], result))

    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")

    dsc_range = dsc.DSCRange()
    extra_offset_value_result = tracepoint.format_string_location
    if formatter_flags.shared_cache or formatter_flags.large_shared_cache != 0:
      if formatter_flags.large_offset_data != 0:
        if formatter_flags.large_offset_data != formatter_flags.large_shared_cache / 2 and not formatter_flags.shared_cache:
          formatter_flags.large_offset_data = formatter_flags.large_shared_cache / 2
          extra_offset_value = "{0:X}{1:08x}".format(formatter_flags.large_offset_data, tracepoint.format_string_location)
        elif formatter_flags.shared_cache:
          formatter_flags.large_offset_data = 8
          extra_offset_value = "{0:X}{1:07x}".format(formatter_flags.large_offset_data, tracepoint.format_string_location)
        else:
          extra_offset_value = "{0:X}{1:08x}".format(formatter_flags.large_offset_data, tracepoint.format_string_location)
        extra_offset_value_result = int(extra_offset_value, 16)
      (fmt, dsc_range) = self._ExtractSharedStrings(tracepoint.format_string_location, extra_offset_value_result, dsc_file)
    else:
      if formatter_flags.absolute:
        uuid_file = self._ExtractAbsoluteStrings(tracepoint.format_string_location, formatter_flags.uuid_file_index, proc_info, message_string_reference)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      elif formatter_flags.uuid_relative:
        uuid_file = self._ExtractAltUUID(formatter_flags.uuid_relative)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      else:
        fmt = self._ExtractFormatStrings(tracepoint.format_string_location, uuid_file)

    found = False
    if data_ref_id != 0:
      for oversize_data in self.oversize_data:
        if oversize_data.first_proc_id == proc_info.first_number_proc_id and oversize_data.second_proc_id == proc_info.second_number_proc_id and oversize_data.data_ref_index == data_ref_id:
          log_data = oversize_data.strings
          found = True
          break
      if not found:
        logger.info("Did not find any oversize log entries from Data Ref ID: {0:d}, First Proc ID: {1:d}, and Second Proc ID: {2:d}".format(data_ref_id, proc_info.first_number_proc_id, proc_info.second_number_proc_id))

    if fmt:
      event_data.message = "".join(backtrace_strings) + self._FormatString(fmt, log_data)
    elif not fmt and not log_data:
      return # Nothing to do ??
    else:
      event_data.message = "UNKNOWN"
      raise errors.ParseError("UNKNOWN")
    event_data.thread_id = hex(tracepoint.thread_identifier)
    event_data.level = self._LOG_TYPES.get(tracepoint.log_type, "Default")
    if activity_id:
      event_data.activity_id = hex(activity_id)
    if ttl_value:
      event_data.ttl = ttl_value
    event_data.pid = proc_info.pid
    event_data.euid = proc_info.euid
    event_data.subsystem = (proc_info.items.get(subsystem_value, ('', '')))[0]
    event_data.category = (proc_info.items.get(subsystem_value, ('', '')))[1]
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    logger.info("Log line: {0!s}".format(event_data.message))
    with open('/tmp/fryoutput.csv', 'a') as f:
      csv.writer(f).writerow([dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString(), event_data.level, event_data.message])

    event = time_events.DateTimeValuesEvent(dfdatetime_apfs_time.APFSTime(timestamp=time), plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)

  #TODO(fryy): Move
  def _ExtractAltUUID(self, uuid):
    uuid_file = [f for f in self.catalog_files if f.uuid == uuid.hex.upper()]
    if len(uuid_file) != 1:
      raise errors.ParseError("Couldn't find UUID file for {0:s}".format(uuid.hex))
      return "UNKNOWN"
    return uuid_file[0]

  def _ExtractAbsoluteStrings(self, original_offset, uuid_file_index, proc_info, message_string_reference):
    logger.info("Extracting absolute strings from UUID file")
    if original_offset & 0x80000000:
      return '%s'

    absolute_uuids = [
      x for x in proc_info.uuids if x.absolute_ref == uuid_file_index and message_string_reference >= x.absolute_offset and message_string_reference-x.absolute_offset < x.size]
    if len(absolute_uuids) != 1:
      raise errors.ParseError("No UUID found for absolute string")
      return "<compose failure [missing precomposed log]>"
    uuid_file = self.catalog.files[absolute_uuids[0].catalog_uuid_index]
    return uuid_file


  def _ExtractFormatStrings(self, offset, uuid_file):
    logger.info("Extracting format string from UUID file")
    return uuid_file.ReadFormatString(offset)

  def _ExtractSharedStrings(self, original_offset, extra_offset, dsc_file):
    logger.info("Extracting format string from shared cache file (DSC)")

    if original_offset & 0x80000000:
      return ('%s', dsc.DSCRange())

    dsc_range = dsc_file.ReadFormatString(extra_offset)
    format_string = self._ReadStructureFromByteStream(
      dsc_range.string[extra_offset - dsc_range.range_offset:], 0, self._GetDataTypeMap('cstring'))

    logger.info("Fmt string: {0:s}".format(format_string))
    return (format_string, dsc_range)

  def ReadItems(self, data_meta, data, offset):
    log_data = []
    deferred_data_items = []
    index = 0
    for _ in range(data_meta.num_items):
      data_item = self._ReadStructureFromByteStream(
        data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data_item'))
      offset += 2 + data_item.item_size
      logger.info("Item data: Type {0:d}".format(data_item.item_type))
      if data_item.item_type in self.FIREHOSE_ITEM_NUMBER_TYPES:
        logger.info("Number: {0!s}".format(data_item.item))
        log_data.append((data_item.item_type, data_item.item_size, data_item.item))
        index += 1
      elif data_item.item_type == self.FIREHOSE_ITEM_STRING_PRIVATE or data_item.item_type in self.FIREHOSE_ITEM_PRIVATE_STRING_TYPES + self.FIREHOSE_ITEM_STRING_TYPES:
        offset -= data_item.item_size
        string_message = self._ReadStructureFromByteStream(
          data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data_item_string_type'))
        offset += data_item.item_size
        deferred_data_items.append((data_item.item_type, string_message.offset, string_message.message_data_size, index))
        index += 1
      elif data_item.item_type in self.FIREHOSE_ITEM_PRECISION_TYPES:
        pass
      elif data_item.item_type == self.FIREHOSE_ITEM_SENSITIVE:
        raise errors.ParseError("Sensitive types not supported -- firehose_log.rs:764")
      else:
        raise errors.ParseError("Unsupported data type ??")
    return (log_data, deferred_data_items, offset)

  def _ParseTracepointData(self, parser_mediator, tracepoint, proc_info, time, private_strings):
    """Parses a log line"""

    logger.info("Parsing log line")
    log_type = self._LOG_TYPES.get(tracepoint.log_type, "Default")
    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY:
      if log_type == 0x80:
        raise errors.ParseError("Non Activity Signpost ??")
      self._ParseNonActivity(parser_mediator, tracepoint, proc_info, time, private_strings)
    elif tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_SIGNPOST:
      self._ParseSignpost(parser_mediator, tracepoint, proc_info, time, private_strings)
    elif tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_ACTIVITY:
      self._ParseActivity(parser_mediator, tracepoint, proc_info, time, private_strings)
    else:
      raise errors.ParseError("Unsupported log activity type: {}".format(tracepoint.log_activity_type))
    return

  def _ReadFirehoseChunkData(self, parser_mediator, chunk_data, data_offset):
    """Reads firehose chunk data.

    Args:
      chunk_data (bytes): firehose chunk data.
      data_offset (int): offset of the firehose chunk relative to the start
          of the chunk set.

    Raises:
      ParseError: if the firehose chunk cannot be read.
    """
    logger.info("Reading Firehose")
    data_type_map = self._GetDataTypeMap('tracev3_firehose_header')

    firehose_header = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)

    logger.info("Firehose Header data: ProcID 1 {0:d} // ProcID 2 {1:d} // TTL {2:d} // CT {3:d}".format(firehose_header.first_number_proc_id, firehose_header.second_number_proc_id, firehose_header.ttl, firehose_header.base_continuous_time))

    proc_id = firehose_header.second_number_proc_id | (firehose_header.first_number_proc_id << 32)
    proc_info = [c for c in self.catalog.process_entries if c.second_number_proc_id | (c.first_number_proc_id << 32) == proc_id]
    if len(proc_info) == 0:
      errors.ParseError("Could not find Process Info block for ID: %d", proc_id)
    else:
      proc_info = proc_info[0]

    private_strings = None
    private_data_len = 0
    if firehose_header.private_data_virtual_offset != 4096:
      private_data_len = 4096 - firehose_header.private_data_virtual_offset
      private_strings = (firehose_header.private_data_virtual_offset, chunk_data[-private_data_len:])

    logger.info("Firehose Header Timestamp: %s", aul_time.TimestampFromContTime(
      self.boot_uuid_ts_list.sync_records, firehose_header.base_continuous_time))

    tracepoint_map = self._GetDataTypeMap('tracev3_firehose_tracepoint')
    chunk_data_offset = 32
    #while chunk_data_offset < chunk_data_size-private_data_len:
    while chunk_data_offset <= firehose_header.public_data_size-16:
      firehose_tracepoint = self._ReadStructureFromByteStream(
          chunk_data[chunk_data_offset:], data_offset + chunk_data_offset, tracepoint_map)
      logger.info("Firehose Tracepoint data: ActivityType {0:d} // Flags {1:d} // ThreadID {2:d} // Datasize {3:d}".format(firehose_tracepoint.log_activity_type, firehose_tracepoint.flags, firehose_tracepoint.thread_identifier, firehose_tracepoint.data_size))

      ct = firehose_header.base_continuous_time + (firehose_tracepoint.continuous_time_lower | (firehose_tracepoint.continuous_time_upper << 32))
      ts = aul_time.FindClosestTimesyncItemInList(self.boot_uuid_ts_list.sync_records, ct)
      time = ts.wall_time + ct - ts.kernel_continuous_timestamp
      self._ParseTracepointData(parser_mediator, firehose_tracepoint, proc_info, time, private_strings)

      chunk_data_offset += 24 + firehose_tracepoint.data_size
      _, alignment = divmod(chunk_data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      chunk_data_offset += alignment

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a timezone information file-like object.

    Args:
      parser_mediator (ParserMediator): a parser mediator.
      file_object (dfvfs.FileIO): a file-like object to parse.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    file_offset = 0
    file_size = file_object.get_size()

    chunkset_index = 0

    while file_offset < file_size:
      chunk_header = self._ReadChunkHeader(file_object, file_offset)
      file_offset += 16

      if chunk_header.chunk_tag == self._CHUNK_TAG_HEADER:
        logger.info("Processing a HEADER (0x1000)")
        self._ReadHeader(file_object, file_offset)

      if chunk_header.chunk_tag == self._CHUNK_TAG_CATALOG:
        logger.info("Processing a CATALOG (0x600B)")
        self.catalog = self._ReadCatalog(parser_mediator, file_object, file_offset)
        chunkset_index = 0

      if chunk_header.chunk_tag == self._CHUNK_TAG_CHUNKSET:
        logger.info("Processing a CHUNKSET (0x600D)")
        self._ReadChunkSet(
          parser_mediator, file_object, file_offset, chunk_header, chunkset_index)
        chunkset_index += 1

      file_offset += chunk_header.chunk_data_size

      _, alignment = divmod(file_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      file_offset += alignment


class AULEventData(events.EventData):
  DATA_TYPE = 'mac:aul:event'

  def __init__(self):
    """Initializes event data."""
    super(AULEventData, self).__init__(data_type=self.DATA_TYPE)
    self.activity_id = None
    self.boot_uuid = None
    self.category = None
    self.euid = None
    self.level = None
    self.library = None
    self.library_uuid = None
    self.message = None
    self.pid = None
    self.process = None
    self.process_uuid = None
    self.subsystem = None
    self.thread_id = None
    self.ttl = None


class AULParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Apple Unified Logging (AUL) files."""

  NAME = 'aul_log'
  DATA_FORMAT = 'Apple Unified Log (AUL) file'

  def __init__(self):
    """Initializes an Apple Unified Logging parser."""
    super(AULParser, self).__init__()
    self.timesync_parser = timesync.TimesyncParser()
    self.tracev3_parser = None
    self.uuid_parser = None
    self.dsc_parser = None

  @classmethod
  def GetFormatSpecification(cls):
    """Retrieves the format specification.

    Returns:
      FormatSpecification: format specification.
    """
    format_specification = specification.FormatSpecification(cls.NAME)
    format_specification.AddNewSignature(
        b'\x00\x10\x00\x00', offset=0)
    return format_specification

  def ParseFileEntry(self, parser_mediator, file_entry):
    """Parses an Apple Unified Logging file.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      file_entry (dfvfs.FileEntry): file entry.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    file_object = file_entry.GetFileObject()
    if not file_object:
      display_name = parser_mediator.GetDisplayName()
      raise errors.WrongParser(
          '[{0:s}] unable to parse tracev3 file {1:s}'.format(
              self.NAME, display_name))

    # Parse timesync files
    file_system = file_entry.GetFileSystem()
    self.timesync_parser.ParseAll(parser_mediator, file_entry, file_system)

    self.uuid_parser = uuidfile.UUIDFileParser(file_entry, file_system)
    self.dsc_parser = dsc.DSCFileParser(file_entry, file_system)

    self.tracev3_parser = TraceV3FileParser(self.timesync_parser, self.uuid_parser, self.dsc_parser)

    try:
      self.tracev3_parser.ParseFileObject(parser_mediator, file_object)
    except (IOError, errors.ParseError) as exception:
      display_name = parser_mediator.GetDisplayName()
      raise errors.WrongParser(
          '[{0:s}] unable to parse tracev3 file {1:s} with error: {2!s}'.format(
              self.NAME, display_name, exception))


manager.ParsersManager.RegisterParser(AULParser)
