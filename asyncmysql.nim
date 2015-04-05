##
## This module implements a (subset of) the MySQL/MariaDB client
## protocol based on asyncnet and asyncdispatch.
##
## No attempt is made to make this look like the C-language
## libmysql API.
##
## This is currently very experimental.
##
## Copyright (c) 2015 William Lewis
##

import strutils, unsigned, asyncnet, asyncdispatch
from rawsockets import AF_INET, SOCK_STREAM

# These are protocol constants; see
#  https://dev.mysql.com/doc/internals/en/overview.html

const
  ResponseCode_OK  : uint8 = 0
  ResponseCode_EOF : uint8 = 254   # Deprecated in mysql 5.7.5
  ResponseCode_ERR : uint8 = 255

  NullColumn       = char(0xFB)

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
    FieldtypeMediumBlob  = uint8(250)
    fieldTypeLongBlob    = uint8(251)
    fieldTypeBlob        = uint8(252)
    fieldTypeVarString   = uint8(253)
    fieldTypeString      = uint8(254)
    fieldTypeGeometry    = uint8(255)

type
  Connection = ref ConnectionObj
  ConnectionObj = object of RootObj
    socket: AsyncSocket               # Bytestream connection
    packet_number: uint8              # Next expected seq number (mod-256)
    remaining_packet_length: range[0 .. 16777215]  # How many bytes remain to be read in current packet

    # Information from the connection setup
    server_version: string
    thread_id: uint32
    server_caps: set[Cap]
    scramble: string
    authentication_plugin: string

  ProtocolError = object of IOError

  # Server response packets: OK and EOF
  ResponseOK = object {.final.}
    ok: bool
    affected_rows: Positive
    last_insert_id: Positive
    status_flags: set[Status]
    warning_count: int
    info: string
    # session_state_changes: seq[ ... ]

  # Server response packet: ERR (which can be thrown as an exception)
  ResponseERR = object of SystemError
    status_flags: set[Status]
    warning_count: int

  ColumnDefinition* = object of RootObj
    catalog     : string
    schema      : string
    table       : string
    orig_table  : string
    name        : string
    orig_name   : string

    charset     : int16
    length      : uint32
    column_type : FieldType
    flags       : set[FieldFlag]
    decimals    : int

## ######################################################################
##
## Basic datatype packers/unpackers

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
  stdmsg.writeln("u16=", result)

proc putU8(buf: var string, val: uint8) {.inline.} =
  buf.add( char(val) )
proc putU8(buf: var string, val: int) {.inline.} =
  buf.add( char(val) )

proc scanLenInt(buf: string, pos: var int): int =
  let b1 = uint8(buf[pos])
  if b1 < 251:
    inc(pos)
    return int(b1)
  if b1 == 0xFC:
    result = int(uint16(buf[pos+1]) + ( uint16(buf[pos+2]) shl 8 ))
    pos = pos + 3
    return
  if b1 == 0xFD:
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
    buf.add( char(0xFC) )
    buf.add( char( val and 0xFF ) )
    buf.add( char( (val shr 8) and 0xFF ) )
  elif val <= 0xFFFFFF:
    buf.add( char(0xFD) )
    buf.add( char( val and 0xFF ) )
    buf.add( char( (val shr 8) and 0xFF ) )
    buf.add( char( (val shr 24) and 0xFF ) )
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
  while pos < high(buf) and buf[pos] != char(0):
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

proc hexdump(buf: openarray[char], fp: File) =
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
proc hexdump(s: string, fp: File) =
  # sigh, why can't I pass a string to an openarray[char] parameter?
  hexdump( cast[seq[char]](s), fp )


## ######################################################################
##
## MySQL-specific packers/unpackers

proc processHeader(c: Connection, hdr: array[4, char]) =
  let plength = int32(hdr[0]) + int32(hdr[1])*256 + int32(hdr[2])*65536
  let pnum = uint8(hdr[3])
  stdmsg.writeln("plen=", plength, ", pnum=", pnum, " (expecting ", c.packet_number, ")")
  if pnum != c.packet_number:
    raise newException(ProtocolError, "Bad packet number")
  c.packet_number += 1
  c.remaining_packet_length = plength

when false:
  # Prototype synchronous code
  proc readExactly(s: Socket, buf: var openarray[char]) =
    var amount_read: int = 0
    while amount_read < len(buf):
      let r = s.recv(addr(buf[amount_read]), len(buf) - amount_read)
      if r < 0:
        socketError(s, r, false)
      if r == 0:
        raise newException(ProtocolError, "Connection closed")
      amount_read += r

  proc readBody(c: Connection): seq[char] =
    result = newSeq[char](c.remaining_packet_length)
    c.socket.readExactly(result)
    c.remaining_packet_length = 0

  proc receivePacket(conn: Connection): string =
    var b: array[4, char]
    readExactly(conn.socket, b)
    processHeader(conn, b)
    let pkt = conn.readBody()
    result = newString(len(pkt))
    # ugly, why are seq[char] and string so hard to interconvert?
    for i in 0 .. high(pkt):
      result[i] = pkt[i]

  proc send(socket: Socket, data: openarray[char]): int =
    # This is horribly ugly, but it seems to be the only way to get
    # something from a seq into a socket
    let p = cast[ptr array[0 .. 1, char]](data)
    return socket.send(p, len(data))
else:
  proc receivePacket(conn:Connection): Future[string] {.async.} =
    let hdr = await conn.socket.recv(4)
    if len(hdr) == 0:
      raise newException(ProtocolError, "Connection closed")
    if len(hdr) != 4:
      raise newException(ProtocolError, "Connection closed unexpectedly")
    let b = cast[ptr array[4,char]](cstring(hdr))
    conn.processHeader(b[])
    if conn.remaining_packet_length == 0:
      return ""
    result = await conn.socket.recv(conn.remaining_packet_length)
    if len(result) == 0:
      raise newException(ProtocolError, "Connection closed unexpectedly")
    if len(result) != conn.remaining_packet_length:
      raise newException(ProtocolError, "TODO finish this part")
    conn.remaining_packet_length = 0

# Caller must have left the first four bytes of the buffer available for
# us to write the packet header.
proc sendPacket(conn: Connection, buf: var string): Future[void] =
  let bodylen = len(buf) - 4
  buf[0] = char( (bodylen and 0xFF) )
  buf[1] = char( ((bodylen shr 8) and 0xFF) )
  buf[2] = char( ((bodylen shr 16) and 0xFF) )
  buf[3] = char( conn.packet_number )
  inc(conn.packet_number)
  hexdump(buf, stdmsg)
  return conn.socket.send(buf)

proc parseInitialGreeting(conn: Connection, greeting: string) =
  let protocolVersion = uint8(greeting[0])
  if protocolVersion != HandshakeV10:
    raise newException(ProtocolError, "Unexpected protocol version: 0x" & toHex(int(protocolVersion), 2))
  var pos = 1
  conn.server_version = scanNulString(greeting, pos)
  conn.thread_id = scanU32(greeting, pos)
  pos += 4
  conn.scramble = greeting[pos .. pos+7]
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
      conn.scramble.add(greeting[pos + 16 .. pos + 16 + moreScram - 8 - 2])
    pos = pos + 16 + ( if moreScram < 20: 12 else: moreScram - 8 )

    if Cap.pluginAuth in conn.server_caps:
      conn.authentication_plugin = scanNulStringX(greeting, pos)

proc add(s: var string, a: seq[char]) =
  for ch in a:
    s.add(ch)

proc writeHandshakeResponse(conn: Connection,
                            username: string,
                            auth_response: seq[char],
                            database: string,
                            auth_plugin: string): Future[void] =
  var buf: string = newStringOfCap(128)
  buf.setLen(4)

  var caps: set[Cap] = { Cap.longPassword, Cap.protocol41, Cap.secureConnection }
  if Cap.longFlag in conn.server_caps:
    incl(caps, Cap.longFlag)
  if auth_response != nil:
    if len(auth_response) > 255:
      incl(caps, Cap.pluginAuthLenencClientData)
  if database != nil:
    incl(caps, Cap.connectWithDb)
  if auth_plugin != nil:
    incl(caps, Cap.pluginAuth)

  # Fixed-length portion
  putU32(buf, cast[uint32](caps))
  putU32(buf, 65536'u32)  # max packet size, TODO: what should I put here?
  buf.add( char(Charset_utf8_ci) )

  # 23 bytes of filler
  for i in 1 .. 23:
    buf.add( char(0) )

  # Our username
  putNulString(buf, username)

  # Authentication data
  if auth_response != nil:
    if Cap.pluginAuthLenencClientData in caps:
      putLenInt(buf, len(auth_response))
      buf.add(auth_response)
    else:
      putU8(buf, len(auth_response))
      buf.add(auth_response)
  else:
    buf.add( char(0) )

  if Cap.connectWithDb in caps:
    putNulString(buf, database)

  if Cap.pluginAuth in caps:
    putNulString(buf, auth_plugin)

  return conn.sendPacket(buf)

proc sendQuery(conn: Connection, query: string): Future[void] =
  var buf: string = newStringOfCap(4 + 1 + len(query))
  buf.setLen(4)
  buf.add( char(Command.query) )
  buf.add(query)
  conn.packet_number = 0
  return conn.sendPacket(buf)

proc receiveMetadata(conn: Connection, count: int): Future[seq[ColumnDefinition]] {.async.}  =
  var received = 0
  result = newSeq[ColumnDefinition](count)
  while received < count:
    let pkt = await conn.receivePacket()
    hexdump(pkt, stdmsg)
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

proc parseRow(pkt: string): seq[string] =
  var pos = 0
  result = newSeq[string]()
  while pos < len(pkt):
    if pkt[pos] == NullColumn:
      result.add(nil)
      inc(pos)
    else:
      result.add(pkt.scanLenStr(pos))

proc blah() {. async .} =
  let sock = newAsyncSocket(AF_INET, SOCK_STREAM)
  await connect(sock, "localhost", Port(3306))
  stdmsg.writeln("woo hoo")
  let conn = Connection(socket:sock)
  parseInitialGreeting(conn, await conn.receivePacket())
  await writeHandshakeResponse(conn,
    "root",
    nil, "mysql", nil)
  hexdump(await conn.receivePacket(), stdmsg)
  await conn.sendQuery("select * from user")
  let r = await conn.receivePacket()
  hexdump(r, stdmsg)
  var p = 0
  let cols = await conn.receiveMetadata(scanLenInt(r, p))
  stdmsg.writeln("it is", cols)
  while true:
    let pkt = await conn.receivePacket()
    pkt.hexdump(stdmsg)
    stdmsg.writeln("row=", repr(parseRow(pkt)))

proc foof() =
  let fut = blah()
  stdmsg.writeln("starting loop")
  waitFor(fut)
  stdmsg.writeln("done")

foof()
