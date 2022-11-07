# -*- coding: utf-8 -*-
"""Mac DNS data helper."""

class DNSFlags(object):
  """DNS Flags Parser.

  See https://github.com/apple-oss-distributions/mDNSResponder
  """

  # Query Response
  QR = 0x8000
  # Op Code
  OPCODE = 0x7800
  _DNS_FLAGS = [
    # Authoritative Answer
    ('AA', 0x0400),
    # Truncated Response
    ('TC', 0x0200),
    # Recursion Desired
    ('RD', 0x0100),
    # Recursion Available
    ('RA', 0x0080),
    # Authentic Data
    ('AD', 0x0020),
    # Checking Disabled
    ('CD', 0x0010)
  ]
  # Response Code
  R = 0x000F

  _QUERY_RESPONSE_FLAG = {
    0: 'Q',
    1: 'R'}

  _DNS_OPCODES = {
    0: 'Query',
    1: 'IQuery',
    2: 'Status',
    3: 'Unassigned',
    4: 'Notify',
    5: 'Update',
    6: 'DSO'}

  _DNS_RESPONSE_CODES = {
    0: 'NoError',
    1: 'FormErr',
    2: 'ServFail',
    3: 'NXDomain',
    4: 'NotImp',
    5: 'Refused',
    6: 'YXDomain',
    7: 'YXRRSet',
    8: 'NXRRSet',
    9: 'NotAuth',
    10: 'NotZone',
    11: 'DSOTypeNI'}

  @classmethod
  def ParseFlags(cls, flags):
    """Parses the DNS reponse flags

    Args:
      flags (int): DNS flags

    Returns:
      str: formatted log message.
    """
    enabled_flags = []
    for (flag, value) in cls._DNS_FLAGS:
      if (flags & value) != 0:
        enabled_flags.append(flag)
    return "{0:s}/{1:s}, {2:s}, {3:s}".format(
      cls._QUERY_RESPONSE_FLAG.get(flags & cls.QR, "?"),
      cls._DNS_OPCODES.get((flags & cls.OPCODE) >> 11, "??"),
      ", ".join(enabled_flags),
      cls._DNS_RESPONSE_CODES.get(flags & cls.R, "??")
      )
