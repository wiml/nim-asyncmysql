## This module implements (a subset of) the MySQL/MariaDB client
## protocol based on asyncnet and asyncdispatch.
##
## No attempt is made to make this look like the C-language
## libmysql API.
##
## This is currently somewhat experimental.
##
## Copyright (c) 2015,2020 William Lewis
##

{.experimental: "notnil".}
import asyncnet, asyncdispatch
import strutils
import std/sha1 as sha1
from endians import nil
from math import fcNormal, fcZero, fcNegZero, fcSubnormal, fcNan, fcInf, fcNegInf

when defined(ssl):
  import net  # needed for the SslContext type

when isMainModule:
  import unittest
  proc hexstr(s: string): string

# These are protocol constants; see
#  https://dev.mysql.com/doc/internals/en/overview.html

const
  ResponseCode_OK  : uint8 = 0
  ResponseCode_EOF : uint8 = 254   # Deprecated in mysql 5.7.5
  ResponseCode_ERR : uint8 = 255

  NullColumn       = char(0xFB)

  LenEnc_16        = 0xFC
  LenEnc_24        = 0xFD
  LenEnc_64        = 0xFE

  HandshakeV10 : uint8 = 0x0A  # Initial handshake packet since MySQL 3.21

  Charset_swedish_ci : uint8 = 0x08
  Charset_utf8_ci    : uint8 = 0x21
  Charset_binary     : uint8 = 0x3f

type
  # These correspond to the bits in the capability words,
  # and the CLIENT_FOO_BAR definitions in mysql. We rely on
  # Nim's set representation being compatible with the
  # C bit-masking convention.
  Cap {.pure.} = enum
    longPassword = 0 # new more secure passwords
    foundRows = 1 # Found instead of affected rows
    longFlag = 2 # Get all column flags
    connectWithDb = 3 # One can specify db on connect
    noSchema = 4 # Don't allow database.table.column
    compress = 5 # Can use compression protocol
    odbc = 6 # Odbc client
    localFiles = 7 # Can use LOAD DATA LOCAL
    ignoreSpace = 8 # Ignore spaces before '('
    protocol41 = 9 # New 4.1 protocol
    interactive = 10 # This is an interactive client
    ssl = 11 # Switch to SSL after handshake
    ignoreSigpipe = 12  # IGNORE sigpipes
    transactions = 13 # Client knows about transactions
    reserved = 14  # Old flag for 4.1 protocol
    secureConnection = 15  # Old flag for 4.1 authentication
    multiStatements = 16  # Enable/disable multi-stmt support
    multiResults = 17  # Enable/disable multi-results
    psMultiResults = 18  # Multi-results in PS-protocol
    pluginAuth = 19  # Client supports plugin authentication
    connectAttrs = 20  # Client supports connection attributes
    pluginAuthLenencClientData = 21  # Enable authentication response packet to be larger than 255 bytes.
    canHandleExpiredPasswords = 22  # Don't close the connection for a connection with expired password.
    sessionTrack = 23
    deprecateEof = 24  # Client no longer needs EOF packet
    sslVerifyServerCert = 30
    rememberOptions = 31

  Status {.pure.} = enum
    inTransaction = 0  # a transaction is active
    autoCommit = 1 # auto-commit is enabled
    moreResultsExist = 3
    noGoodIndexUsed = 4
    noIndexUsed = 5
    cursorExists = 6 # Used by Binary Protocol Resultset
    lastRowSent = 7
    dbDropped = 8
    noBackslashEscapes = 9
    metadataChanged = 10
    queryWasSlow = 11
    psOutParams = 12
    inTransactionReadOnly = 13 # in a read-only transaction
    sessionStateChanged = 14 # connection state information has changed

  # These correspond to the CMD_FOO definitions in mysql.
  # Commands marked "internal to the server", and commands
  # only used by the replication protocol, are commented out
  Command {.pure.} = enum
    # sleep = 0
    quiT = 1
    initDb = 2
    query = 3
    fieldList = 4
    createDb = 5
    dropDb = 6
    refresh = 7
    shutdown = 8
    statistics = 9
    processInfo = 10
    # connect = 11
    processKill = 12
    debug = 13
    ping = 14
    # time = 15
    # delayedInsert = 16
    changeUser = 17

    # Replication commands
    # binlogDump = 18
    # tableDump = 19
    # connectOut = 20
    # registerSlave = 21
    # binlogDumpGtid = 30

    # Prepared statements
    statementPrepare = 22
    statementExecute = 23
    statementSendLongData = 24
    statementClose = 25
    statementReset = 26

    # Stored procedures
    setOption = 27
    statementFetch = 28

    # daemon = 29
    resetConnection = 31

  FieldFlag* {.pure.} = enum
    notNull = 0 # Field can't be NULL
    primaryKey = 1 # Field is part of a primary key
    uniqueKey = 2 # Field is part of a unique key
    multipleKey = 3 # Field is part of a key
    blob = 4 # Field is a blob
    unsigned = 5 # Field is unsigned
    zeroFill = 6 # Field is zerofill
    binary = 7 # Field is binary

    # The following are only sent to new clients (what is "new"? 4.1+?)
    enumeration = 8 # field is an enum
    autoIncrement = 9 # field is a autoincrement field
    timeStamp = 10 # Field is a timestamp
    isSet = 11 # Field is a set
    noDefaultValue = 12 # Field doesn't have default value
    onUpdateNow = 13 # Field is set to NOW on UPDATE
    isNum = 15 # Field is num (for clients)

  FieldType* = enum
    fieldTypeDecimal     = uint8(0)
    fieldTypeTiny        = uint8(1)
    fieldTypeShort       = uint8(2)
    fieldTypeLong        = uint8(3)
    fieldTypeFloat       = uint8(4)
    fieldTypeDouble      = uint8(5)
    fieldTypeNull        = uint8(6)
    fieldTypeTimestamp   = uint8(7)
    fieldTypeLongLong    = uint8(8)
    fieldTypeInt24       = uint8(9)
    fieldTypeDate        = uint8(10)
    fieldTypeTime        = uint8(11)
    fieldTypeDateTime    = uint8(12)
    fieldTypeYear        = uint8(13)
    fieldTypeVarchar     = uint8(15)
    fieldTypeBit         = uint8(16)
    fieldTypeNewDecimal  = uint8(246)
    fieldTypeEnum        = uint8(247)
    fieldTypeSet         = uint8(248)
    fieldTypeTinyBlob    = uint8(249)
    fieldTypeMediumBlob  = uint8(250)
    fieldTypeLongBlob    = uint8(251)
    fieldTypeBlob        = uint8(252)
    fieldTypeVarString   = uint8(253)
    fieldTypeString      = uint8(254)
    fieldTypeGeometry    = uint8(255)

  CursorType* {.pure.} = enum
    noCursor             = 0
    readOnly             = 1
    forUpdate            = 2
    scrollable           = 3

  # This represents a value returned from the server when using
  # the prepared statement / binary protocol. For convenience's sake
  # we combine multiple wire types into the nearest Nim type.
  ResultValueType = enum
    rvtNull,
    rvtInteger,
    rvtLong,
    rvtULong,
    rvtFloat32,
    rvtFloat64,
    rvtDate,
    rvtTime,
    rvtDateTime,
    rvtString,
    rvtBlob
  ResultValue* = object
    ## A value returned from the server when using the prepared statement
    ## (binary) protocol. This might contain a numeric or string type
    ## or NULL. To check for NULL, use `isNil`; attempts to read a value
    ## from a NULL result will result in a `ValueError`.
    case typ: ResultValueType
      of rvtInteger:
        intVal: int
      of rvtLong:
        longVal: int64
      of rvtULong:
        uLongVal: uint64
      of rvtString, rvtBlob:
        strVal: string
      of rvtNull:
        discard
      of rvtFloat32:
        floatVal: float32
      of rvtFloat64:
        doubleVal: float64
      of rvtDate, rvtTime, rvtDateTime:
        discard # TODO

  ResultString* = object
    ## A value returned from the server when using the text protocol.
    ## This contains either a string or an SQL NULL.
    case isNull: bool
    of false:
      value: string
    of true:
      discard

  ParamBindingType = enum
    paramNull,
    paramString,
    paramBlob,
    paramInt,
    paramUInt,
    paramFloat,
    paramDouble,
    # paramLazyString, paramLazyBlob,
  ParameterBinding* = object
    ## This represents a value we're sending to the server as a parameter.
    ## Since parameters' types are always sent along with their values,
    ## we choose the wire type of integers based on the particular value
    ## we're sending each time.
    case typ: ParamBindingType
      of paramNull:
        discard
      of paramString, paramBlob:
        strVal: string
      of paramInt:
        intVal: int64
      of paramUInt:
        uintVal: uint64
      of paramFloat:
        floatVal: float32
      of paramDouble:
        doubleVal: float64

type
  nat24 = range[0 .. 16777215]
  Connection* = ref ConnectionObj     ## A database connection handle.
  ConnectionObj* = object of RootObj
    socket: AsyncSocket not nil       # Bytestream connection
    packet_number: uint8              # Next expected seq number (mod-256)

    # Information from the connection setup
    server_version*: string
    thread_id*: uint32
    server_caps: set[Cap]

    # Other connection parameters
    client_caps: set[Cap]

  ProtocolError* = object of IOError
    ## ProtocolError is thrown if we get something we don't understand
    ## or expect. This is generally a fatal error as far as this connection
    ## is concerned, since we might have lost framing, packet sequencing,
    ## etc.. Unexpected connection closure will also result in this exception.

  # Server response packets: OK and EOF
  ResponseOK* {.final.} = object
    ## Status information returned from the server after each successful
    ## command.
    eof               : bool  # True if EOF packet, false if OK packet
    affected_rows*    : Natural
    last_insert_id*   : Natural
    status_flags*     : set[Status]
    warning_count*    : Natural
    info*             : string
    # session_state_changes: seq[ ... ]

  # Server response packet: ERR (which can be thrown as an exception)
  ResponseERR* = object of CatchableError
    ## This exception is thrown when a command fails.
    error_code*: uint16  ## A MySQL-specific error number
    sqlstate*: string    ## An ANSI SQL state code

  ColumnDefinition* {.final.} = object
    catalog*     : string
    schema*      : string
    table*       : string
    orig_table*  : string
    name*        : string
    orig_name*   : string

    charset      : int16
    length*      : uint32
    column_type* : FieldType
    flags*       : set[FieldFlag]
    decimals*    : int

  ResultSet*[T] {.final.} = object
    status*     : ResponseOK
    columns*    : seq[ColumnDefinition]
    rows*       : seq[seq[T]]

  PreparedStatement* = ref PreparedStatementObj
  PreparedStatementObj = object
    statement_id: array[4, char]
    parameters: seq[ColumnDefinition]
    columns: seq[ColumnDefinition]
    warnings: Natural

type sqlNull = distinct tuple[]
const SQLNULL*: sqlNull = sqlNull( () )
  ## `SQLNULL` is a singleton value corresponding to SQL's NULL.
  ## This is used to send a NULL value for a parameter when
  ## executing a prepared statement.

const advertisedMaxPacketSize: uint32 = 65536 # max packet size, TODO: what should I put here?

# ######################################################################
#
# Forward declarations

proc selectDatabase*(conn: Connection, database: string): Future[ResponseOK]

# ######################################################################
#
# Basic datatype packers/unpackers

# Integers

proc scanU32(buf: string, pos: int): uint32 =
  result = uint32(buf[pos]) + `shl`(uint32(buf[pos+1]), 8'u32) + (uint32(buf[pos+2]) shl 16'u32) + (uint32(buf[pos+3]) shl 24'u32)

proc putU32(buf: var string, val: uint32) =
  buf.add( char( val and 0xff ) )
  buf.add( char( (val shr 8)  and 0xff ) )
  buf.add( char( (val shr 16) and 0xff ) )
  buf.add( char( (val shr 24) and 0xff ) )

proc scanU16(buf: string, pos: int): uint16 =
  result = uint16(buf[pos]) + (uint16(buf[pos+1]) shl 8'u16)
proc putU16(buf: var string, val: uint16) =
  buf.add( char( val and 0xFF ) )
  buf.add( char( (val shr 8) and 0xFF ) )

proc putU8(buf: var string, val: uint8) {.inline.} =
  buf.add( char(val) )
proc putU8(buf: var string, val: range[0..255]) {.inline.} =
  buf.add( char(val) )

proc scanU64(buf: string, pos: int): uint64 =
  let l32 = scanU32(buf, pos)
  let h32 = scanU32(buf, pos+4)
  return uint64(l32) + ( (uint64(h32) shl 32 ) )

proc putS64(buf: var string, val: int64) =
  let compl: uint64 = cast[uint64](val)
  buf.putU32(uint32(compl and 0xFFFFFFFF'u64))
  buf.putU32(uint32(compl shr 32))

proc scanLenInt(buf: string, pos: var int): int =
  let b1 = uint8(buf[pos])
  if b1 < 251:
    inc(pos)
    return int(b1)
  if b1 == LenEnc_16:
    result = int(uint16(buf[pos+1]) + ( uint16(buf[pos+2]) shl 8 ))
    pos = pos + 3
    return
  if b1 == LenEnc_24:
    result = int(uint32(buf[pos+1]) + ( uint32(buf[pos+2]) shl 8 ) + ( uint32(buf[pos+3]) shl 16 ))
    pos = pos + 4
    return
  return -1

proc putLenInt(buf: var string, val: int) =
  if val < 0:
    raise newException(ProtocolError, "trying to send a negative lenenc-int")
  elif val < 251:
    buf.add( char(val) )
  elif val < 65536:
    buf.add( char(LenEnc_16) )
    buf.add( char( val and 0xFF ) )
    buf.add( char( (val shr 8) and 0xFF ) )
  elif val <= 0xFFFFFF:
    buf.add( char(LenEnc_24) )
    buf.add( char( val and 0xFF ) )
    buf.add( char( (val shr 8) and 0xFF ) )
    buf.add( char( (val shr 16) and 0xFF ) )
  else:
    raise newException(ProtocolError, "lenenc-int too long for me!")

# Strings
proc scanNulString(buf: string, pos: var int): string =
  result = ""
  while buf[pos] != char(0):
    result.add(buf[pos])
    inc(pos)
  inc(pos)
proc scanNulStringX(buf: string, pos: var int): string =
  result = ""
  while pos <= high(buf) and buf[pos] != char(0):
    result.add(buf[pos])
    inc(pos)
  inc(pos)

proc putNulString(buf: var string, val: string) =
  buf.add(val)
  buf.add( char(0) )

proc scanLenStr(buf: string, pos: var int): string =
  let slen = scanLenInt(buf, pos)
  if slen < 0:
    raise newException(ProtocolError, "lenenc-int: is 0x" & toHex(int(buf[pos]), 2))
  result = substr(buf, pos, pos+slen-1)
  pos = pos + slen

proc putLenStr(buf: var string, val: string) =
  putLenInt(buf, val.len)
  buf.add(val)


# Floating point numbers. We assume that the wire protocol is always
# little-endian IEEE-754 (because all the world's a Vax^H^H^H 386),
# and we assume that the native representation is also IEEE-754 (but
# we check that second assumption in our unit tests).
proc scanIEEE754Single(buf: string, pos: int): float32 =
  endians.littleEndian32(addr(result), unsafeAddr(buf[pos]))
proc scanIEEE754Double(buf: string, pos: int): float64 =
  endians.littleEndian64(addr(result), unsafeAddr(buf[pos]))

proc putIEEE754(buf: var string, val: float32) =
  let oldLen = buf.len()
  buf.setLen(oldLen + 4)
  endians.littleEndian32(addr(buf[oldLen]), unsafeAddr val)
proc putIEEE754(buf: var string, val: float64) =
  let oldLen = buf.len()
  buf.setLen(oldLen + 8)
  endians.littleEndian64(addr(buf[oldLen]), unsafeAddr val)

when isMainModule: suite "Packing/unpacking of primitive types":
  test "Integers":
    var buf: string = ""
    putLenInt(buf, 0)
    putLenInt(buf, 1)
    putLenInt(buf, 250)
    putLenInt(buf, 251)
    putLenInt(buf, 252)
    putLenInt(buf, 512)
    putLenInt(buf, 640)
    putLenInt(buf, 65535)
    putLenInt(buf, 65536)
    putLenInt(buf, 15715755)
    putU32(buf, uint32(65535))
    putU32(buf, uint32(65536))
    putU32(buf, 0x80C00AAA'u32)
    check "0001fafcfb00fcfc00fc0002fc8002fcfffffd000001fdabcdefffff000000000100aa0ac080" == hexstr(buf)

    var pos: int = 0
    check 0         == scanLenInt(buf, pos)
    check 1         == scanLenInt(buf, pos)
    check 250       == scanLenInt(buf, pos)
    check 251       == scanLenInt(buf, pos)
    check 252       == scanLenInt(buf, pos)
    check 512       == scanLenInt(buf, pos)
    check 640       == scanLenInt(buf, pos)
    check 0x0FFFF   == scanLenInt(buf, pos)
    check 0x10000   == scanLenInt(buf, pos)
    check 15715755  == scanLenInt(buf, pos)
    check 65535'u32 == scanU32(buf, pos)
    check 65535'u16 == scanU16(buf, pos)
    check 255'u16   == scanU16(buf, pos+1)
    check 0'u16     == scanU16(buf, pos+2)
    pos += 4
    check 65536'u32 == scanU32(buf, pos)
    pos += 4
    check 0x80C00AAA'u32 == scanU32(buf, pos)
    pos += 4
    check 0x80C00AAA00010000'u64 == scanU64(buf, pos-8)
    check len(buf) == pos

  test "Integers (bit-walking tests)":
    for bit in 0..63:
      var byhand: string = "\xFF"
      var test: string

      for b_off in 0..7:
        if b_off == bit div 8:
          byhand.add(chr(0x01 shl (bit mod 8)))
        else:
          byhand.add(chr(0))

      if bit < 16:
        let v16: uint16 = (1'u16) shl bit
        check scanU16(byhand, 1) == v16
        test = "\xFF"
        putU16(test, v16)
        test &= "\x00\x00\x00\x00\x00\x00"
        check test == byhand
        check hexstr(test) == hexstr(byhand)

      if bit < 32:
        let v32: uint32 = (1'u32) shl bit
        check scanU32(byhand, 1) == v32
        test = "\xFF"
        putU32(test, v32)
        test &= "\x00\x00\x00\x00"
        check test == byhand

      if bit < 63:
        test = "\xFF"
        putS64(test, (1'i64) shl bit)
        check test == byhand
        check hexstr(test) == hexstr(byhand)

      let v64: uint64 = (1'u64) shl bit
      check scanU64(byhand, 1) == v64

  const e32: float32 = 0.00000011920928955078125'f32

  test "Floats":
    var buf: string = ""

    putIEEE754(buf, 1.0'f32)
    putIEEE754(buf, e32)
    putIEEE754(buf, 1.0'f32 + e32)
    check "0000803f000000340100803f" == hexstr(buf)
    check:
      scanIEEE754Single(buf, 0) == 1.0'f32
      scanIEEE754Single(buf, 4) == e32
      scanIEEE754Single(buf, 8) == 1.0'f32 + e32

    # Non-word-aligned
    check:
      scanIEEE754Single("XAB\x01\x49Y", 1) == 0x81424 + 0.0625'f32

  test "Doubles":
    var buf: string = ""

    putIEEE754(buf, -2.0'f64)
    putIEEE754(buf, float64(e32))
    putIEEE754(buf, 1024'f64 + float64(e32))
    check "00000000000000c0000000000000803e0000080000009040" == hexstr(buf)
    check:
      scanIEEE754Double(buf, 0) == -2'f64
      scanIEEE754Double(buf, 8) == float64(e32)
      scanIEEE754Double(buf, 16) == 1024'f64 + float64(e32)

    # Non-word-aligned
    check:
      scanIEEE754Double("XYZGFEDCB\xFA\x42QRS", 3) == float64(0x1A42434445464) + 0.4375'f64

proc hexdump(buf: openarray[char], fp: File) {.used.} =
  var pos = low(buf)
  while pos <= high(buf):
    for i in 0 .. 15:
      fp.write(' ')
      if i == 8: fp.write(' ')
      let p = i+pos
      fp.write( if p <= high(buf): toHex(int(buf[p]), 2) else: "  " )
    fp.write("  |")
    for i in 0 .. 15:
      var ch = ( if (i+pos) > high(buf): ' ' else: buf[i+pos] )
      if ch < ' ' or ch > '~':
        ch = '.'
      fp.write(ch)
    pos += 16
    fp.write("|\n")


# ######################################################################
#
# Parameter and result packers/unpackers

proc addTypeUnlessNULL(p: ParameterBinding, pkt: var string) =
  case p.typ
  of paramNull:
    return
  of paramString:
    pkt.add(char(fieldTypeString))
    pkt.add(char(0))
  of paramBlob:
    pkt.add(char(fieldTypeBlob))
    pkt.add(char(0))
  of paramInt:
    if p.intVal >= 0:
      if p.intVal < 256'i64:
        pkt.add(char(fieldTypeTiny))
      elif p.intVal < 65536'i64:
        pkt.add(char(fieldTypeShort))
      elif p.intVal < (65536'i64 * 65536'i64):
        pkt.add(char(fieldTypeLong))
      else:
        pkt.add(char(fieldTypeLongLong))
      pkt.add(char(0x80))
    else:
      if p.intVal >= -128:
        pkt.add(char(fieldTypeTiny))
      elif p.intVal >= -32768:
        pkt.add(char(fieldTypeShort))
      else:
        pkt.add(char(fieldTypeLongLong))
      pkt.add(char(0))
  of paramUInt:
    if p.uintVal < (65536'u64 * 65536'u64):
      pkt.add(char(fieldTypeLong))
    else:
      pkt.add(char(fieldTypeLongLong))
    pkt.add(char(0x80))
  of paramFloat:
    pkt.add(char(fieldTypeFloat))
    pkt.add(char(0))
  of paramDouble:
    pkt.add(char(fieldTypeDouble))
    pkt.add(char(0))

proc addValueUnlessNULL(p: ParameterBinding, pkt: var string) =
  case p.typ
  of paramNull:
    return
  of paramString, paramBlob:
    putLenStr(pkt, p.strVal)
  of paramInt:
    if p.intVal >= 0:
      pkt.putU8(p.intVal and 0xFF)
      if p.intVal >= 256:
        pkt.putU8((p.intVal shr 8) and 0xFF)
        if p.intVal >= 65536:
          pkt.putU16( ((p.intVal shr 16) and 0xFFFF).uint16 )
          if p.intVal >= (65536'i64 * 65536'i64):
            pkt.putU32(uint32(p.intVal shr 32))
    else:
      if p.intVal >= -128:
        pkt.putU8(uint8(p.intVal + 256))
      elif p.intVal >= -32768:
        pkt.putU16(uint16(p.intVal + 65536))
      else:
        pkt.putS64(p.intVal)
  of paramUInt:
    putU32(pkt, uint32(p.uintVal and 0xFFFFFFFF'u64))
    if p.uintVal >= 0xFFFFFFFF'u64:
      putU32(pkt, uint32(p.uintVal shr 32))
  of paramFloat:
    pkt.putIEEE754(p.floatVal)
  of paramDouble:
    pkt.putIEEE754(p.doubleVal)

proc approximatePackedSize(p: ParameterBinding): int {.inline.} =
  case p.typ
  of paramNull:
    return 0
  of paramString, paramBlob:
    return 5 + len(p.strVal)
  of paramInt, paramUInt, paramFloat:
    return 4
  of paramDouble:
    return 8

proc asParam*(n: sqlNull): ParameterBinding {. inline .} = ParameterBinding(typ: paramNull)

proc asParam*(n: typeof(nil)): ParameterBinding {. deprecated("Do not use nil for NULL parameters, use SQLNULL") .} = ParameterBinding(typ: paramNull)

proc asParam*(s: string): ParameterBinding =
  ParameterBinding(typ: paramString, strVal: s)

proc asParam*(i: int): ParameterBinding {. inline .} = ParameterBinding(typ: paramInt, intVal: i)

proc asParam*(i: uint): ParameterBinding =
  if i > uint(high(int)):
    ParameterBinding(typ: paramUInt, uintVal: uint64(i))
  else:
    ParameterBinding(typ: paramInt, intVal: int64(i))

proc asParam*(i: int64): ParameterBinding =
  ParameterBinding(typ: paramInt, intVal: i)

proc asParam*(i: uint64): ParameterBinding =
  if i > uint64(high(int)):
    ParameterBinding(typ: paramUInt, uintVal: i)
  else:
    ParameterBinding(typ: paramInt, intVal: int64(i))

proc asParam*(b: bool): ParameterBinding = ParameterBinding(typ: paramInt, intVal: if b: 1 else: 0)

proc asParam*(f: float32): ParameterBinding {. inline .} =
  ParameterBinding(typ: paramFloat, floatVal:f)

proc asParam*(f: float64): ParameterBinding {. inline .} =
  ParameterBinding(typ: paramDouble, doubleVal:f)

proc isNil*(v: ResultValue): bool {.inline.} = v.typ == rvtNull

proc `$`*(v: ResultValue): string =
  ## Produce an approximate string representation of the value. This
  ## should mainly be restricted to debugging uses, since it is impossible
  ## to distingiuish between, *e.g.*, a NULL value and the four-character
  ## string "NULL".
  case v.typ
  of rvtNull:
    return "NULL"
  of rvtString, rvtBlob:
    return v.strVal
  of rvtInteger:
    return $(v.intVal)
  of rvtLong:
    return $(v.longVal)
  of rvtULong:
    return $(v.uLongVal)
  of rvtFloat32:
    return $(v.floatVal)
  of rvtFloat64:
    return $(v.doubleVal)
  else:
    return "(unrepresentable!)"

{.push overflowChecks: on .}
proc toNumber[T: SomeInteger](v: ResultValue): T {.inline.} =
  case v.typ
  of rvtInteger:
    return T(v.intVal)
  of rvtLong:
    return T(v.longVal)
  of rvtULong:
    return T(v.uLongVal)
  of rvtNull:
    raise newException(ValueError, "NULL value")
  else:
    raise newException(ValueError, "cannot convert " & $(v.typ) & " to " & $(T))

# Converters can't be generic; we need to explicitly instantiate
# the ones we think might be needed.
converter asInt8*(v: ResultValue): uint8 = return toNumber[uint8](v)
converter asInt*(v: ResultValue): int = return toNumber[int](v)
converter asUInt*(v: ResultValue): uint = return toNumber[uint](v)
converter asInt64*(v: ResultValue): int64 = return toNumber[int64](v)
converter asUInt64*(v: ResultValue): uint64 = return toNumber[uint64](v)

proc toFloat[T: SomeFloat](v: ResultValue): T {.inline.} =
  case v.typ
  of rvtFloat32:
    return v.floatVal
  of rvtFloat64:
    return v.doubleVal
  of rvtNULL:
    raise newException(ValueError, "NULL value")
  else:
    raise newException(ValueError, "cannot convert " & $(v.typ) & " to float")

converter asFloat32*(v: ResultValue): float32 = toFloat[float32](v)
converter asFloat64*(v: ResultValue): float64 = toFloat[float64](v)
{. pop .}

converter asString*(v: ResultValue): string =
  ## If the value is a string, return it; otherwise raise a `ValueError`.
  case v.typ
  of rvtNull:
    raise newException(ValueError, "NULL value")
  of rvtString, rvtBlob:
    return v.strVal
  else:
    raise newException(ValueError, "cannot convert " & $(v.typ) & " to string")

converter asBool*(v: ResultValue): bool =
  ## If the value is numeric, return it as a boolean; otherwise
  ## raise a `ValueError`. Note that `NULL` is neither true nor
  ## false and will raise.
  case v.typ
  of rvtInteger:
    return v.intVal != 0
  of rvtLong:
    return v.longVal != 0
  of rvtULong:
    return v.uLongVal != 0
  of rvtNull:
    raise newException(ValueError, "NULL value")
  else:
    raise newException(ValueError, "cannot convert " & $(v.typ) & " to boolean")

proc `==`*(v: ResultValue, s: string): bool =
  ## Compare the result value to a string.
  ## NULL values are not equal to any string.
  ## Non-string non-NULL values will result in an exception.
  case v.typ
  of rvtNull:
    return false
  of rvtString, rvtBlob:
    return v.strVal == s
  else:
    raise newException(ValueError, "cannot convert " & $(v.typ) & " to string")

proc floatEqualsInt[F: SomeFloat, I: SomeInteger](v: F, n: I): bool =
  ## Compare a float to an integer. Note that this is inherently a
  ## dodgy operation (which is why it's not overloading `==`). Floats
  ## are inexact, and each float corresponds to a range of real numbers;
  ## for larger numbers, a single float value can be "equal to" many
  ## different integers. (Or maybe it''s equal to none of them if it
  ## can't represent any of them exactly — it really depends on what
  ## you're modeling with that float, doesn''t it?) Anyway, for my particular
  ## case I don't care about that.

  # Infinities, NaNs, etc., are not equal to any integer. Subnormals
  # are also always less than 1 (and nonzero) so cannot be integers.
  case math.classify(v)
  of fcNormal:
    if n == 0:
      return false
    else:
      return v == F(n)  # kludge
  of fcZero, fcNegZero:
    return n == 0
  of fcSubnormal, fcNan, fcInf, fcNegInf:
    return false

proc `==`[S: SomeSignedInt, U: SomeUnsignedInt](s: S, u: U): bool =
  ## Safely compare a signed and an unsigned integer of possibly
  ## different widths.
  if s < 0:
    return false
  when sizeof(U) >= sizeof(S):
    if u > U(high(S)):
      return false
    else:
      return S(u) == s
  else:
    if s > S(high(U)):
      return false
    else:
      return U(s) == u

when (NimMajor, NimMinor) < (1, 2) and uint isnot uint64:
  # Support for Nim < 1.2
  proc `==`(a: uint, b: uint64): bool =
    return uint64(a) == b

proc `==`*[T: SomeInteger](v: ResultValue, n: T): bool =
  ## Compare the result value to an integer.
  ## NULL values are not equal to any integer.
  ## Non-numeric non-NULL values (strings, etc.) will result in an exception.
  ##
  ## As a special case, this allows comparing a floating point ResultValue
  ## to an integer.
  case v.typ
  of rvtInteger:
    return v.intVal == n
  of rvtLong:
    return v.longVal == n
  of rvtULong:
    return n == v.uLongVal
  of rvtFloat32:
    return floatEqualsInt(v.floatVal, n)
  of rvtFloat64:
    return floatEqualsInt(v.doubleVal, n)
  of rvtNull:
    return false
  else:
    raise newException(ValueError, "cannot compare " & $(v.typ) & " to integer")

proc `==`*[F: SomeFloat](v: ResultValue, n: F): bool =
  ## Compare the result value to a float.
  ## NULL values are not equal to anything.
  ## Non-float values (including integers) will result in an exception.
  case v.typ
  of rvtFloat32:
    return v.floatVal == n
  of rvtFloat64:
    return v.doubleVal == n
  of rvtNull:
    return false
  else:
    raise newException(ValueError, "cannot compare " & $(v.typ) & " to floating-point number")

proc `==`*(v: ResultValue, b: bool): bool =
  ## Compare a result value to a boolean.
  ##
  ## The MySQL wire protocol does
  ## not have an explicit boolean type, so this tests an integer type against
  ## zero. NULL values are not equal to true *or* false (therefore,
  ## `if v == true:` is not equivalent to `if v:`: the latter will raise
  ## an exception if v is NULL). Non-integer values will result in an exception.
  if v.typ == rvtNull:
    return false
  else:
    return bool(v) == b

proc isNil*(v: ResultString): bool {.inline.} = v.isNull

proc `$`*(v: ResultString): string =
  ## Produce an approximate string representation of the value. This
  ## should mainly be restricted to debugging uses, since it is impossible
  ## to distingiuish between a NULL value and the four-character
  ## string "NULL".
  case v.isNull
  of true:
    return "NULL"
  of false:
    return v.value

converter asString*(v: ResultString): string =
  ## Return the result as a string.
  ## Raise `ValueError` if the result is NULL.
  case v.isNull:
  of true:
    raise newException(ValueError, "NULL value")
  of false:
    return v.value

proc `==`*(a: ResultString, b: ResultString): bool =
  ## Compare two result strings. **Note:** This does not
  ## follow SQL semantics; NULL will compare equal to NULL.
  case a.isNull
  of true:
    return b.isNull
  of false:
    return (not b.isNull) and (a.value == b.value)

proc `==`*(a: ResultString, b: string): bool =
  ## Compare a result to a string. NULL results are not
  ## equal to any string.
  case a.isNull
  of true:
    return false
  of false:
    return (a.value == b)

proc asResultString*(s: string): ResultString {.inline.} =
  ResultString(isNull: false, value: s)
proc asResultString*(n: sqlNull): ResultString {.inline.} =
  ResultString(isNull: true)

# ######################################################################
#
# MySQL packet packers/unpackers

proc processHeader(c: Connection, hdr: array[4, char]): nat24 =
  result = int32(hdr[0]) + int32(hdr[1])*256 + int32(hdr[2])*65536
  let pnum = uint8(hdr[3])
  if pnum != c.packet_number:
    raise newException(ProtocolError, "Bad packet number (got sequence number " & $(pnum) & ", expected " & $(c.packet_number) & ")")
  c.packet_number += 1

proc receivePacket(conn:Connection, drop_ok: bool = false): Future[string] {.async.} =
  let hdr = await conn.socket.recv(4)
  if len(hdr) == 0:
    if drop_ok:
      return ""
    else:
      raise newException(ProtocolError, "Connection closed")
  if len(hdr) != 4:
    raise newException(ProtocolError, "Connection closed unexpectedly")
  let b = cast[ptr array[4,char]](cstring(hdr))
  let packet_length = conn.processHeader(b[])
  if packet_length == 0:
    return ""
  result = await conn.socket.recv(packet_length)
  if len(result) == 0:
    raise newException(ProtocolError, "Connection closed unexpectedly")
  if len(result) != packet_length:
    raise newException(ProtocolError, "TODO finish this part")

# Caller must have left the first four bytes of the buffer available for
# us to write the packet header.
proc sendPacket(conn: Connection, buf: var string, reset_seq_no = false): Future[void] =
  let bodylen = len(buf) - 4
  buf[0] = char( (bodylen and 0xFF) )
  buf[1] = char( ((bodylen shr 8) and 0xFF) )
  buf[2] = char( ((bodylen shr 16) and 0xFF) )
  if reset_seq_no:
    conn.packet_number = 0
  buf[3] = char( conn.packet_number )
  inc(conn.packet_number)
  # hexdump(buf, stdmsg)
  return conn.socket.send(buf)

type
  greetingVars {.final.} = object
    scramble: string
    authentication_plugin: string

# This implements the "mysql_native_password" auth plugin,
# which is the only auth we support.
proc mysql_native_password_hash(scramble: string, password: string): string =
  let phash1 = sha1.Sha1Digest(sha1.secureHash(password))
  let phash2 = sha1.Sha1Digest(sha1.secureHash(cast[array[20, char]](phash1)))

  var ctx = sha1.newSha1State()
  ctx.update(scramble)
  ctx.update(cast[array[20, char]](phash2))
  let rhs = ctx.finalize()

  result = newString(1+high(phash1))
  for i in 0 .. high(phash1):
    result[i] = char(phash1[i] xor rhs[i])
const mysql_native_password_plugin = "mysql_native_password"

when isMainModule:
  test "Password hash":
    # Test vectors captured from tcp traces of official mysql
    check hexstr(mysql_native_password_hash("L\\i{NQ09k2W>p<yk/DK+",
                                            "foo")) ==
                 "f828cd1387160a4c920f6c109d37285d281f7c85"

    check hexstr(mysql_native_password_hash("<G.N}OR-(~e^+VQtrao-",
                                            "aaaaaaaaaaaaaaaaaaaabbbbbbbbbb")) ==
                 "78797fae31fc733107e778ee36e124436761bddc"

proc parseInitialGreeting(conn: Connection, greeting: string): greetingVars =
  let protocolVersion = uint8(greeting[0])
  if protocolVersion != HandshakeV10:
    raise newException(ProtocolError, "Unexpected protocol version: 0x" & toHex(int(protocolVersion), 2))
  var pos = 1
  conn.server_version = scanNulString(greeting, pos)
  conn.thread_id = scanU32(greeting, pos)
  pos += 4
  result.scramble = greeting[pos .. pos+7]
  let cflags_l = scanU16(greeting, pos + 8 + 1)
  conn.server_caps = cast[set[Cap]](cflags_l)
  pos += 11

  if not (Cap.protocol41 in conn.server_caps):
    raise newException(ProtocolError, "Old (pre-4.1) server protocol")

  if len(greeting) >= (pos+5):
    let cflags_h = scanU16(greeting, pos+3)
    conn.server_caps = cast[set[Cap]]( uint32(cflags_l) + (uint32(cflags_h) shl 16) )

    let moreScram = ( if Cap.protocol41 in conn.server_caps: int(greeting[pos+5]) else: 0 )
    if moreScram > 8:
      result.scramble.add(greeting[pos + 16 .. pos + 16 + moreScram - 8 - 2])
    pos = pos + 16 + ( if moreScram < 20: 12 else: moreScram - 8 )

    if Cap.pluginAuth in conn.server_caps:
      result.authentication_plugin = scanNulStringX(greeting, pos)

proc computeHandshakeResponse(conn: Connection,
                              greetingPacket: string,
                              username, password: string,
                              database: string,
                              starttls: bool): string =

  let greet: greetingVars = conn.parseInitialGreeting(greetingPacket)

  let server_caps = conn.server_caps
  var caps: set[Cap] = { Cap.longPassword,
                         Cap.protocol41,
                         Cap.secureConnection }
  if Cap.longFlag in server_caps:
    incl(caps, Cap.longFlag)

  if len(database) > 0 and Cap.connectWithDb in conn.server_caps:
    incl(caps, Cap.connectWithDb)

  if starttls:
    if Cap.ssl notin conn.server_caps:
      raise newException(ProtocolError, "Server does not support SSL")
    else:
      incl(caps, Cap.ssl)

  # Figure out our authentication response. Right now we only
  # support the mysql_native_password_hash method.
  var auth_response: string
  var auth_plugin: string

  # password authentication
  if password.len == 0:
    # The caller passes a 0-length password to indicate no password, since
    # we don't have nillable strings.
    auth_response = ""
    auth_plugin = ""
  else: # in future: if greet.authentication_plugin == "" or greet.authentication_plugin == mysql_native_password
    auth_response = mysql_native_password_hash(greet.scramble, password)
    if Cap.pluginAuth in server_caps:
      auth_plugin = mysql_native_password_plugin
      incl(caps, Cap.pluginAuth)
    else:
      auth_plugin = ""

  # Do we need pluginAuthLenencClientData ?
  if len(auth_response) > 255:
    if Cap.pluginAuthLenencClientData in server_caps:
      incl(caps, Cap.pluginAuthLenencClientData)
    else:
      raise newException(ProtocolError, "server cannot handle long auth_response")

  conn.client_caps = caps

  var buf: string = newStringOfCap(128)
  buf.setLen(4)

  # Fixed-length portion
  putU32(buf, cast[uint32](caps))
  putU32(buf, advertisedMaxPacketSize)
  buf.add( char(Charset_utf8_ci) )

  # 23 bytes of filler
  for i in 1 .. 23:
    buf.add( char(0) )

  # Our username
  putNulString(buf, username)

  # Authentication data
  let authLen = len(auth_response)
  if Cap.pluginAuthLenencClientData in caps:
    putLenInt(buf, authLen)
  else:
    putU8(buf, len(auth_response))
  buf.add(auth_response)

  if Cap.connectWithDb in caps:
    putNulString(buf, database)

  if Cap.pluginAuth in caps:
    putNulString(buf, auth_plugin)

  return buf

proc sendCommand(conn: Connection, cmd: Command): Future[void] =
  ## Send a simple, argument-less command.
  var buf: string = newString(5)
  buf[4] = char(cmd)
  return conn.sendPacket(buf, reset_seq_no=true)

proc sendQuery(conn: Connection, query: string): Future[void] =
  var buf: string = newStringOfCap(4 + 1 + len(query))
  buf.setLen(4)
  buf.add( char(Command.query) )
  buf.add(query)
  return conn.sendPacket(buf, reset_seq_no=true)

proc receiveMetadata(conn: Connection, count: Positive): Future[seq[ColumnDefinition]] {.async.}  =
  var received = 0
  result = newSeq[ColumnDefinition](count)
  while received < count:
    let pkt = await conn.receivePacket()
    # hexdump(pkt, stdmsg)
    if uint8(pkt[0]) == ResponseCode_ERR or uint8(pkt[0]) == ResponseCode_EOF:
      raise newException(ProtocolError, "TODO")
    var pos = 0
    result[received].catalog = scanLenStr(pkt, pos)
    result[received].schema = scanLenStr(pkt, pos)
    result[received].table = scanLenStr(pkt, pos)
    result[received].orig_table = scanLenStr(pkt, pos)
    result[received].name = scanLenStr(pkt, pos)
    result[received].orig_name = scanLenStr(pkt, pos)
    let extras_len = scanLenInt(pkt, pos)
    if extras_len < 10 or (pos+extras_len > len(pkt)):
      raise newException(ProtocolError, "truncated column packet")
    result[received].charset = int16(scanU16(pkt, pos))
    result[received].length = scanU32(pkt, pos+2)
    result[received].column_type = FieldType(uint8(pkt[pos+6]))
    result[received].flags = cast[set[FieldFlag]](scanU16(pkt, pos+7))
    result[received].decimals = int(pkt[pos+9])
    inc(received)
  let endPacket = await conn.receivePacket()
  if uint8(endPacket[0]) != ResponseCode_EOF:
    raise newException(ProtocolError, "Expected EOF after column defs, got something else")

proc parseTextRow(pkt: string): seq[ResultString] =
  var pos = 0
  result = newSeq[ResultString]()
  while pos < len(pkt):
    if pkt[pos] == NullColumn:
      result.add( ResultString(isNull: true) )
      inc(pos)
    else:
      result.add( ResultString(isNull: false, value: pkt.scanLenStr(pos)) )

# EOF is signaled by a packet that starts with 0xFE, which is
# also a valid length-encoded-integer. In order to distinguish
# between the two cases, we check the length of the packet: EOFs
# are always short, and an 0xFE in a result row would be followed
# by at least 65538 bytes of data.
proc isEOFPacket(pkt: string): bool =
  result = (len(pkt) >= 1) and (pkt[0] == char(ResponseCode_EOF)) and (len(pkt) < 9)

# Error packets are simpler to detect, because 0xFF is not (yet?)
# valid as the start of a length-encoded-integer.
proc isERRPacket(pkt: string): bool = (len(pkt) >= 3) and (pkt[0] == char(ResponseCode_ERR))

proc isOKPacket(pkt: string): bool = (len(pkt) >= 3) and (pkt[0] == char(ResponseCode_OK))

proc parseErrorPacket(pkt: string): ref ResponseERR not nil =
  new(result)
  result.error_code = scanU16(pkt, 1)
  var pos: int
  if len(pkt) >= 9 and pkt[3] == '#':
    result.sqlstate = pkt.substr(4, 8)
    pos = 9
  else:
    pos = 3
  result.msg = pkt[pos .. high(pkt)]

proc parseOKPacket(conn: Connection, pkt: string): ResponseOK =
  result.eof = false
  var pos: int = 1
  result.affected_rows = scanLenInt(pkt, pos)
  result.last_insert_id = scanLenInt(pkt, pos)
  # We always supply Cap.protocol41 in client caps
  result.status_flags = cast[set[Status]]( scanU16(pkt, pos) )
  result.warning_count = scanU16(pkt, pos+2)
  pos = pos + 4
  if Cap.sessionTrack in conn.client_caps:
    result.info = scanLenStr(pkt, pos)
  else:
    result.info = scanNulStringX(pkt, pos)

proc parseEOFPacket(pkt: string): ResponseOK =
  result.eof = true
  result.warning_count = scanU16(pkt, 1)
  result.status_flags = cast[set[Status]]( scanU16(pkt, 3) )

proc expectOK(conn: Connection, ctxt: string): Future[ResponseOK] {.async.} =
  let pkt = await conn.receivePacket()
  if isERRPacket(pkt):
    raise parseErrorPacket(pkt)
  elif isOKPacket(pkt):
    return parseOKPacket(conn, pkt)
  else:
    raise newException(ProtocolError, "unexpected response to " & ctxt)

proc prepareStatement*(conn: Connection, query: string): Future[PreparedStatement] {.async.} =
  ## Prepare a statement for future execution. The returned statement handle
  ## must only be used with this connection. This is equivalent to
  ## the `mysql_stmt_prepare()` function in the standard C API.
  var buf: string = newStringOfCap(4 + 1 + len(query))
  buf.setLen(4)
  buf.add( char(Command.statementPrepare) )
  buf.add(query)
  await conn.sendPacket(buf, reset_seq_no=true)
  let pkt = await conn.receivePacket()
  if isERRPacket(pkt):
    raise parseErrorPacket(pkt)
  if pkt[0] != char(ResponseCode_OK) or len(pkt) < 12:
    raise newException(ProtocolError, "Unexpected response to STMT_PREPARE (len=" & $(pkt.len) & ", first byte=0x" & toHex(int(pkt[0]), 2) & ")")
  let num_columns = scanU16(pkt, 5)
  let num_params = scanU16(pkt, 7)
  let num_warnings = scanU16(pkt, 10)

  new(result)
  result.warnings = num_warnings
  for b in 0 .. 3: result.statement_id[b] = pkt[1+b]
  if num_params > 0'u16:
    result.parameters = await conn.receiveMetadata(int(num_params))
  else:
    result.parameters = newSeq[ColumnDefinition](0)
  if num_columns > 0'u16:
    result.columns = await conn.receiveMetadata(int(num_columns))

proc prepStmtBuf(stmt: PreparedStatement, buf: var string, cmd: Command, cap: int = 9) =
  buf = newStringOfCap(cap)
  buf.setLen(9)
  buf[4] = char(cmd)
  for b in 0..3: buf[b+5] = stmt.statement_id[b]

proc closeStatement*(conn: Connection, stmt: PreparedStatement): Future[void] =
  ## Indicate to the server that this prepared statement is no longer
  ## needed. Note that statement handles are not closed automatically
  ## if garbage-collected, and will continue to occupy a statement
  ## handle on the server side until the connection is closed.
  var buf: string
  stmt.prepStmtBuf(buf, Command.statementClose)
  return conn.sendPacket(buf, reset_seq_no=true)
proc resetStatement*(conn: Connection, stmt: PreparedStatement): Future[void] =
  var buf: string
  stmt.prepStmtBuf(buf, Command.statementReset)
  return conn.sendPacket(buf, reset_seq_no=true)

proc formatBoundParams(stmt: PreparedStatement, params: openarray[ParameterBinding]): string =
  if len(params) != len(stmt.parameters):
    raise newException(ValueError, "Wrong number of parameters supplied to prepared statement (got " & $len(params) & ", statement expects " & $len(stmt.parameters) & ")")
  var approx = 14 + ( (params.len + 7) div 8 ) + (params.len * 2)
  for p in params:
    approx += p.approximatePackedSize()
  stmt.prepStmtBuf(result, Command.statementExecute, cap = approx)
  result.putU8(uint8(CursorType.noCursor))
  result.putU32(1) # "iteration-count" always 1
  if stmt.parameters.len == 0:
    return
  # Compute the null bitmap
  var ch = 0
  for p in 0 .. high(stmt.parameters):
    let bit = p mod 8
    if bit == 0 and p > 0:
      result.add(char(ch))
      ch = 0
    if params[p].typ == paramNull:
      ch = ch or ( 1 shl bit )
  result.add(char(ch))
  result.add(char(1)) # new-params-bound flag
  for p in params:
    p.addTypeUnlessNULL(result)
  for p in params:
    p.addValueUnlessNULL(result)

proc parseBinaryRow(columns: seq[ColumnDefinition], pkt: string): seq[ResultValue] =
  let column_count = columns.len
  let bitmap_len = (column_count + 9) div 8
  if len(pkt) < (1 + bitmap_len) or pkt[0] != char(0):
    raise newException(ProtocolError, "Truncated or incorrect binary result row")
  newSeq(result, column_count)
  var pos = 1 + bitmap_len
  for ix in 0 .. column_count-1:
    # First, check whether this column's bit is set in the null
    # bitmap. The bitmap is offset by 2, for no apparent reason.
    let bitmap_index = ix + 2
    let bitmap_entry = uint8(pkt[ 1 + (bitmap_index div 8) ])
    if (bitmap_entry and uint8(1 shl (bitmap_index mod 8))) != 0'u8:
      # This value is NULL
      result[ix] = ResultValue(typ: rvtNull)
    else:
      let typ = columns[ix].column_type
      let uns = FieldFlag.unsigned in columns[ix].flags
      case typ
      of fieldTypeNull:
        result[ix] = ResultValue(typ: rvtNull)
      of fieldTypeTiny:
        let v = pkt[pos]
        inc(pos)
        let ext = (if uns: int(cast[uint8](v)) else: int(cast[int8](v)))
        result[ix] = ResultValue(typ: rvtInteger, intVal: ext)
      of fieldTypeShort, fieldTypeYear:
        let v = int(scanU16(pkt, pos))
        inc(pos, 2)
        let ext = (if uns or (v <= 32767): v else: 65536 - v)
        result[ix] = ResultValue(typ: rvtInteger, intVal: ext)
      of fieldTypeInt24, fieldTypeLong:
        let v = scanU32(pkt, pos)
        inc(pos, 4)
        var ext: int
        if not uns and (typ == fieldTypeInt24) and v >= 8388608'u32:
          ext = 16777216 - int(v)
        elif not uns and (typ == fieldTypeLong):
          ext = int( cast[int32](v) ) # rely on 2's-complement reinterpretation here
        else:
          ext = int(v)
        result[ix] = ResultValue(typ: rvtInteger, intVal: ext)
      of fieldTypeLongLong:
        let v = scanU64(pkt, pos)
        inc(pos, 8)
        if uns:
          result[ix] = ResultValue(typ: rvtULong, uLongVal: v)
        else:
          result[ix] = ResultValue(typ: rvtLong, longVal: cast[int64](v))
      of fieldTypeFloat:
        result[ix] = ResultValue(typ: rvtFloat32,
                                 floatVal: scanIEEE754Single(pkt, pos))
        inc(pos, 4)
      of fieldTypeDouble:
        result[ix] = ResultValue(typ: rvtFloat64,
                                 doubleVal: scanIEEE754Double(pkt, pos))
        inc(pos, 8)
      of fieldTypeTime, fieldTypeDate, fieldTypeDateTime, fieldTypeTimestamp:
        raise newException(Exception, "Not implemented, TODO")
      of fieldTypeTinyBlob, fieldTypeMediumBlob, fieldTypeLongBlob, fieldTypeBlob, fieldTypeBit:
        result[ix] = ResultValue(typ: rvtBlob, strVal: scanLenStr(pkt, pos))
      of fieldTypeVarchar, fieldTypeVarString, fieldTypeString, fieldTypeDecimal, fieldTypeNewDecimal:
        result[ix] = ResultValue(typ: rvtString, strVal: scanLenStr(pkt, pos))
      of fieldTypeEnum, fieldTypeSet, fieldTypeGeometry:
        raise newException(ProtocolError, "Unexpected field type " & $(typ) & " in resultset")

proc finishEstablishingConnection(conn: Connection, database: string): Future[void] {.async.} =
  # await confirmation from the server
  let pkt = await conn.receivePacket()
  if isOKPacket(pkt):
    discard
  elif isERRPacket(pkt):
    raise parseErrorPacket(pkt)
  else:
    raise newException(ProtocolError, "Unexpected packet received after sending client handshake")

  # Normally we bundle the initial database selection into the
  # connection setup exchange, but if we couldn't do that, then do it
  # here.
  if len(database) > 0 and Cap.connectWithDb notin conn.client_caps:
    discard await conn.selectDatabase(database)

when declared(SslContext) and defined(ssl):
  proc establishConnection*(sock: AsyncSocket not nil, username: string, password: string, database: string = "", sslHostname: string, ssl: SslContext): Future[Connection] {.async.} =
    ## Establish a connection, requesting SSL (TLS). The `sslHostname` and
    ## `ssl` parameters are as used by `asyncnet.wrapConnectedSocket`.
    if isNil(ssl):
      raise newException(ValueError, "nil SSL context")
    if isNil(sock):
      raise newException(ValueError, "nil socket")
    else:
      result = Connection(socket: sock)
    let pkt = await result.receivePacket()
    var response = computeHandshakeResponse(result, pkt,
                                            username, password, database,
                                            starttls = true)

    # MySQL's equivalent of STARTTLS: we send a sort of stub response
    # here, which is a prefix of the real response just containing our
    # client caps flags, then do SSL setup, and send the entire response
    # over the encrypted connection.
    var stub: string = response[0 ..< 36]
    await result.sendPacket(stub)

    # The server will respond with the SSL SERVER_HELLO packet.
    wrapConnectedSocket(ssl, result.socket,
                        handshake = handshakeAsClient,
                        hostname = sslHostname)
    # and, once the encryption is negotiated, we will continue
    # with the real handshake response.
    await result.sendPacket(response)

    # And finish the handshake
    await result.finishEstablishingConnection(database)

proc establishConnection*(sock: AsyncSocket not nil, username: string, password: string, database: string = ""): Future[Connection] {.async.} =
  ## Establish a database session. The caller is responsible for setting up
  ## the underlying socket, which will be adopted by the returned `Connection`
  ## instance and closed when the connection is closed.
  ##
  ## If `password` is non-empty,  password authentication is performed
  ## (it is not possible to perform password authentication with a zero-length
  ## password using this library). If `database` is non-empty, the named
  ## database will be selected.
  if isNil(sock):
    raise newException(ValueError, "nil socket")
  else:
    result = Connection(socket: sock)
  let pkt = await result.receivePacket()
  var response = computeHandshakeResponse(result, pkt,
                                          username, password, database,
                                          starttls = false)
  await result.sendPacket(response)
  await result.finishEstablishingConnection(database)

proc textQuery*(conn: Connection, query: string): Future[ResultSet[ResultString]] {.async.} =
  ## Perform a query using the text protocol, returning a single result set.
  await conn.sendQuery(query)
  let pkt = await conn.receivePacket()
  if isOKPacket(pkt):
    # Success, but no rows returned.
    result.status = parseOKPacket(conn, pkt)
    result.columns = @[]
    result.rows = @[]
  elif isERRPacket(pkt):
    # Some kind of failure.
    raise parseErrorPacket(pkt)
  else:
    var p = 0
    let column_count = scanLenInt(pkt, p)
    result.columns = await conn.receiveMetadata(column_count)
    var rows: seq[seq[ResultString]]
    newSeq(rows, 0)
    while true:
      let pkt = await conn.receivePacket()
      if isEOFPacket(pkt):
        result.status = parseEOFPacket(pkt)
        break
      elif isOKPacket(pkt):
        result.status = parseOKPacket(conn, pkt)
        break
      elif isERRPacket(pkt):
        raise parseErrorPacket(pkt)
      else:
        rows.add(parseTextRow(pkt))
    result.rows = rows
  return

proc performPreparedQuery(conn: Connection, stmt: PreparedStatement, st: Future[void]): Future[ResultSet[ResultValue]] {.async.} =
  await st
  let initialPacket = await conn.receivePacket()
  if isOKPacket(initialPacket):
    # Success, but no rows returned.
    result.status = parseOKPacket(conn, initialPacket)
    result.columns = @[]
    result.rows = @[]
  elif isERRPacket(initialPacket):
    # Some kind of failure.
    raise parseErrorPacket(initialPacket)
  else:
    var p = 0
    let column_count = scanLenInt(initialPacket, p)
    result.columns = await conn.receiveMetadata(column_count)
    var rows: seq[seq[ResultValue]]
    newSeq(rows, 0)
    while true:
      let pkt = await conn.receivePacket()
      # hexdump(pkt, stdmsg)
      if isEOFPacket(pkt):
        result.status = parseEOFPacket(pkt)
        break
      elif isERRPacket(pkt):
        raise parseErrorPacket(pkt)
      else:
        rows.add(parseBinaryRow(result.columns, pkt))
    result.rows = rows

proc preparedQuery*(conn: Connection, stmt: PreparedStatement, params: varargs[ParameterBinding, asParam]): Future[ResultSet[ResultValue]] =
  ## Perform a query using the binary (prepared-statement) protocol,
  ## returning a single result set.
  var pkt = formatBoundParams(stmt, params)
  var sent = conn.sendPacket(pkt, reset_seq_no=true)
  return performPreparedQuery(conn, stmt, sent)

proc selectDatabase*(conn: Connection, database: string): Future[ResponseOK] {.async.} =
  ## Select a database.
  ## This is equivalent to the `mysql_select_db()` function in the
  ## standard C API.
  var buf: string = newStringOfCap(4 + 1 + len(database))
  buf.setLen(4)
  buf.add( char(Command.initDb) )
  buf.add(database)
  await conn.sendPacket(buf, reset_seq_no=true)
  return await conn.expectOK("COM_INIT_DB")

proc ping*(conn: Connection): Future[ResponseOK] {.async.} =
  ## Send a ping packet to the server to check for liveness.
  ## This is equivalent to the `mysql_ping()` function in the
  ## standard C API.
  await conn.sendCommand(Command.ping)
  return await conn.expectOK("COM_PING")

proc close*(conn: Connection): Future[void] {.async.} =
  ## Close the connection to the database, including the underlying socket.
  await conn.sendCommand(Command.quiT)
  let pkt = await conn.receivePacket(drop_ok=true)
  conn.socket.close()

# ######################################################################
#
# Internal tests
# These don't try to test everything, just basic things and things
# that won't be exercised by functional testing against a server


when isMainModule:
  proc hexstr(s: string): string =
    result = ""
    let chs = "0123456789abcdef"
    for ch in s:
      let i = int(ch)
      result.add(chs[ (i and 0xF0) shr 4])
      result.add(chs[  i and 0x0F ])

  test "Parameter packing":
    let dummy_param = ColumnDefinition()
    var sth: PreparedStatement
    new(sth)
    sth.statement_id = ['\0', '\xFF', '\xAA', '\x55' ]
    sth.parameters = @[dummy_param, dummy_param, dummy_param, dummy_param, dummy_param, dummy_param, dummy_param, dummy_param]

    # Small numbers
    let buf = formatBoundParams(sth, [ asParam(0), asParam(1), asParam(127), asParam(128), asParam(255), asParam(256), asParam(-1), asParam(-127) ])
    let h = "000000001700ffaa5500010000000001" &  # packet header
            "01800180018001800180028001000100" &  # wire type info
            "00017f80ff0001ff81"                  # packed values
    check h == hexstr(buf)

    # Numbers and NULLs
    sth.parameters = sth.parameters & dummy_param
    let buf2 = formatBoundParams(sth, [ asParam(-128), asParam(-129), asParam(-255), asParam(nil), asParam(SQLNULL), asParam(-256), asParam(-257), asParam(-32768), asParam(SQLNULL)  ])
    let h2 = "000000001700ffaa550001000000180101" &  # packet header
             "010002000200020002000200" &            # wire type info
             "807fff01ff00fffffe0080"                # packed values
    check h2 == hexstr(buf2)

    # More values (strings, etc)
    let buf3 = formatBoundParams(sth, [ asParam("hello"), asParam(SQLNULL),
      asParam(0xFFFF), asParam(0xF1F2F3), asParam(0xFFFFFFFF), asParam(0xFFFFFFFFFF),
      asParam(-12885), asParam(-2160069290), asParam(low(int64) + 512) ])
    let h3 = "000000001700ffaa550001000000020001" &  # packet header
             "fe000280038003800880020008000800"   &  # wire type info
             "0568656c6c6ffffff3f2f100ffffffffffffffffff000000abcd56f53f7fffffffff0002000000000080"
    check h3 == hexstr(buf3)

    # Floats and doubles
    const e32: float32 = 0.00000011920928955078125'f32
    let buf4 = formatBoundParams(sth, [
      asParam(0'f32), asParam(65535'f32),
      asParam(e32), asParam(1 + e32),
      asParam(0'f64), asParam(-1'f64),
      asParam(float64(e32)), asParam(1 + float64(e32)), asParam(1024 + float64(e32)) ])
    let h4 = "000000001700ffaa550001000000000001" &   # packet header
             "040004000400040005000500050005000500" & # wire type info
             "0000000000ff7f47000000340100803f" & # floats
             "0000000000000000000000000000f0bf" & # doubles
             "000000000000803e000000200000f03f0000080000009040"
    check h4 == hexstr(buf4)
