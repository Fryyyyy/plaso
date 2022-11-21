# -*- coding: utf-8 -*-
"""Mac DNS data helper."""

class DNS(object):
  """DNS Parser.

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

  _DNS_RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    13: 'HINFO',
    15: 'MX',
    16: 'TXT',
    17: 'RP',
    18: 'AFSDB',
    24: 'SIG',
    25: 'KEY',
    28: 'AAAA',
    29: 'LOC',
    33: 'SRV',
    35: 'NAPTR',
    36: 'KX',
    37: 'CERT',
    39: 'DNAME',
    42: 'APL',
    43: 'DS',
    44: 'SSHFP',
    45: 'IPSECKEY',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    49: 'DHCID',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    52: 'TLSA',
    53: 'SMIMEA',
    55: 'HIP',
    59: 'CDS',
    60: 'CDNSKEY',
    61: 'OPENPGPKEY',
    62: 'CSYNC',
    63: 'ZONEMD',
    64: 'SVCB',
    65: 'HTTPS',
    108: 'EUI48',
    109: 'EUI64',
    249: 'TKEY',
    250: 'TSIG',
    256: 'URI',
    257: 'CAA',
    32768: 'TA',
    32769: 'DLV'
  }

  _DNS_PROTOCOLS = {
    1: 'UDP',
    2: 'TCP',
    4: 'HTTPS'
  }

  _DNS_REASONS = {
    1: 'no-data',
    2: 'nxdomain',
    3: 'no-dns-service',
    4: 'query-suppressed',
    5: 'server error'
  }

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
      'R' if flags & cls.QR else 'Q',
      cls._DNS_OPCODES.get((flags & cls.OPCODE) >> 11, '??'),
      ', '.join(enabled_flags),
      cls._DNS_RESPONSE_CODES.get(flags & cls.R, '???')
      )

  @classmethod
  def GetRecordType(cls, record_type):
    """Retrieves the DNS record type

    Args:
      record_type (int): DNS record type code

    Returns:
      str: DNS record type
    """
    return cls._DNS_RECORD_TYPES.get(record_type, str(record_type))

  @classmethod
  def GetProtocolType(cls, protocol_type):
    """Retrieves the DNS protocol type

    Args:
      protocol_type (int): DNS protocol type code

    Returns:
      str: DNS protocol type
    """
    return cls._DNS_PROTOCOLS.get(protocol_type, str(protocol_type))

  @classmethod
  def GetReasons(cls, reason_type):
    """Retrieves the DNS reason type

    Args:
      reason_type (int): DNS reason type code

    Returns:
      str: DNS reason type
    """
    return cls._DNS_REASONS.get(reason_type, str(reason_type))
