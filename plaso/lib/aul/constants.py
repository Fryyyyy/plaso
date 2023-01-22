# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) constants."""


# Supported Versions
SUPPORTED_DSC_VERSIONS = [(1, 0), (2, 0)]

# ARM Processor Timebase Adjustment
ARM_TIMEBASE_NUMERATOR = 125
ARM_TIMEBASE_DENOMINATOR = 3

# Flags
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

# Activity Types
FIREHOSE_LOG_ACTIVITY_TYPE_ACTIVITY = 0x2
FIREHOSE_LOG_ACTIVITY_TYPE_TRACE = 0x3
FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY = 0x4
FIREHOSE_LOG_ACTIVITY_TYPE_SIGNPOST = 0x6
FIREHOSE_LOG_ACTIVITY_TYPE_LOSS = 0x7

# Item Types
FIREHOSE_ITEM_DYNAMIC_PRECISION_TYPE = 0x0
FIREHOSE_ITEM_NUMBER_TYPES = [0x0, 0x2]
FIREHOSE_ITEM_STRING_PRIVATE = 0x1
FIREHOSE_ITEM_PRIVATE_STRING_TYPES = [
    0x21, 0x25, 0x31, 0x35, 0x41]
FIREHOSE_ITEM_STRING_TYPES = [
    0x20, 0x22, 0x30, 0x32, 0x40, 0x42, 0xf2]
FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES = [
    0x30, 0x31, 0x32]
FIREHOSE_ITEM_STRING_BASE64_TYPE = 0xf2
FIREHOSE_ITEM_PRECISION_TYPES = [0x10, 0x12]
FIREHOSE_ITEM_SENSITIVE = 0x45

# Log Types
LOG_TYPES = {
    0x01: 'Info',
    0x02: 'Debug',
    0x03: 'Useraction',
    0x10: 'Error',
    0x11: 'Fault',
    0x40: 'Thread Signpost Event',
    0x41: 'Thread Signpost Start',
    0x42: 'Thread Signpost End',
    0x80: 'Process Signpost Event',
    0x81: 'Process Signpost Start',
    0x82: 'Process Signpost End',
    0xc0: 'System Signpost Event',
    0xc1: 'System Signpost Start',
    0xc2: 'System Signpost End'}

# MBR Details Types
USER_TYPES = [0x24, 0xA0, 0xA4]
UID_TYPES = [0x23, 0xA3]
GROUP_TYPES = [0x44]
GID_TYPES = [0xC3]

# Legal LocationManagerStateTracker Size values
LEGAL_LOCATION_SIZES = [64, 72]
