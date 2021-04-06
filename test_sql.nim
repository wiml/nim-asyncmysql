import asyncmysql, asyncdispatch, asyncnet, os, parseutils
from nativesockets import AF_INET, SOCK_STREAM

import net
import strutils

var database_name: string
var port: int = 3306
var host_name: string = "localhost"
var user_name: string
var pass_word: string
var ssl: bool = false
var allow_mitm: bool = false
var verbose: bool = false

when defined(ssl):
  ssl = true

proc doTCPConnect(dbn: string = ""): Future[Connection] {.async.} =
  let sock = newAsyncSocket(AF_INET, SOCK_STREAM)
  await connect(sock, host_name, Port(port))
  if sock.isNil:
    raise newException(ValueError, "nil socket")
  else:
    if ssl:
      when defined(ssl):
        let ctx = newContext(verifyMode = (if allow_mitm: CVerifyNone else: CVerifyPeer))
        return await establishConnection(sock, user_name, database=dbn, password = pass_word, sslHostname = host_name, ssl=ctx)
      else:
        raise newException(CatchableError, "ssl is not enabled in this build")
    return await establishConnection(sock, user_name, database=dbn, password = pass_word)

proc getCurrentDatabase(conn: Connection): Future[ResultString] {.async.} =
  let rslt = await conn.textQuery("select database()")
  doAssert(len(rslt.columns) == 1, "wrong number of result columns")
  doAssert(len(rslt.rows) == 1, "wrong number of result rows")
  return rslt.rows[0][0]

proc checkCurrentCipher(conn: Connection): Future[bool] {.async.} =
  let rslt = await conn.textQuery("show session status like 'Ssl_cipher'")
  doAssert(len(rslt.columns) == 2, "wrong number of result columns")
  doAssert(len(rslt.rows) == 1, "wrong number of result rows")
  echo "  ", rslt.rows[0][0], " = ", rslt.rows[0][1]
  let ssl_cipher = rslt.rows[0][1]
  if ssl_cipher.isNil or ssl_cipher == "":
    return false
  else:
    return true

proc connTest(): Future[Connection] {.async.} =
  echo "Connecting (with initial db: ", database_name, ")"
  let conn1 = await doTCPConnect(dbn = database_name)
  echo "Checking current database is correct"
  let conn1db1 = await getCurrentDatabase(conn1)
  if conn1db1 != database_name:
    echo "FAIL (actual db: ", $conn1db1, ")"
  echo "Connecting (without initial db)"
  let conn2 = await doTCPConnect()
  let conn2db1 = await getCurrentDatabase(conn2)
  if not isNil(conn2db1):
    echo "FAIL (db should be NULL, is: ", $conn2db1, ")"
  discard await conn2.selectDatabase(database_name)
  let conn2db2 = await getCurrentDatabase(conn2)
  if conn2db2 != database_name:
    echo "FAIL (db should be: ", database_name, " is: ", conn2db2, ")"
  echo "Checking TIDs (", conn1.thread_id, ", ", conn2.thread_id, ")"
  let rslt = await conn1.textQuery("show processlist");
  var saw_conn1 = false
  var saw_conn2 = false
  for row in rslt.rows:
    if row[0] == $(conn1.thread_id):
      doAssert(saw_conn1 == false, "Multiple rows with conn1's TID")
      saw_conn1 = true
    if row[0] == $(conn2.thread_id):
      doAssert(saw_conn2 == false, "Multiple rows with conn1's TID")
      saw_conn2 = true
  doAssert(saw_conn1, "Didn't see conn1's TID")
  doAssert(saw_conn2, "Didn't see conn2's TID")
  let ssl1 = conn1.checkCurrentCipher()
  let ssl2 = conn2.checkCurrentCipher()
  await `and`(ssl1, ssl2)
  doAssert(ssl1.read() == ssl)
  doAssert(ssl2.read() == ssl)
  let p1 = conn1.ping()
  let p2 = conn2.ping()
  await `and`(p1, p2)
  echo "Closing second connection"
  await conn2.close()
  return conn1

template assertEq(T: typedesc, got: untyped, expect: untyped, msg: string = "incorrect value") =
  let aa: T = got
  bind instantiationInfo
  {.line: instantiationInfo().}:
    if aa != expect:
      raiseAssert("assertEq(" & astToStr(got) & ", " & astToStr(expect) & ") failed (got " & repr(aa) & "): " & msg)

template assertEqrs(got: untyped, expect: varargs[ResultString, asResultString]) =
  bind instantiationInfo
  let aa: seq[ResultString] = got
  let count = aa.len
  {.line: instantiationInfo().}:
    if count != expect.len:
      raiseAssert(format("assertEqrs($1, ...) failed (got $2 columns, expected $3)", astToStr(got), count, aa.len))
    for col in 0 .. high(aa):
      if aa[col] != expect[col]:
        raiseAssert(format("assertEqrs($1, $2) failed (mismatch at index $3)", astToStr(got), expect, col))

proc numberTests(conn: Connection): Future[void] {.async.} =
  echo "Setting up table for numeric tests..."
  discard await conn.textQuery("drop table if exists num_tests")
  discard await conn.textQuery("create table num_tests (s text, u8 tinyint unsigned, s8 tinyint, u int unsigned, i int, b bigint)")

  echo "Testing numeric parameters"
  # Insert values using the binary protocol
  let insrow = await conn.prepareStatement("insert into `num_tests` (s, u8, s8, u, i, b) values (?, ?, ?, ?, ?, ?)")
  discard await conn.preparedQuery(insrow, "one", 1, 1, 1, 1, 1)
  discard await conn.preparedQuery(insrow, "max", 255, 127, 4294967295, 2147483647, 9223372036854775807'u64)
  discard await conn.preparedQuery(insrow, "min", 0, -128, 0, -2147483648, (-9223372036854775807'i64 - 1))
  discard await conn.preparedQuery(insrow, "foo", 128, -127, 256, -32767, -32768)
  discard await conn.preparedQuery(insrow, "feh", 130'f32, -128'f64, 256.1'f32,
                                   -2100000000'f32, 2147483649.0125'f64)
  await conn.closeStatement(insrow)

  # Read them back using the text protocol
  let r1 = await conn.textQuery("select s, u8, s8, u, i, b from num_tests order by u8 asc")
  assertEq(int, r1.columns.len(), 6, "column count")
  assertEq(int, r1.rows.len(), 5, "row count")
  assertEq(string, r1.columns[0].name, "s")
  assertEq(string, r1.columns[5].name, "b")

  assertEqrs(r1.rows[0], "min", "0", "-128", "0", "-2147483648", "-9223372036854775808")
  assertEqrs(r1.rows[1], "one", "1", "1", "1", "1", "1")
  assertEqrs(r1.rows[2], "foo", "128", "-127", "256", "-32767", "-32768")
  assertEqrs(r1.rows[3], "feh", "130", "-128", "256", "-2100000000", "2147483649")
  assertEqrs(r1.rows[4], "max", "255", "127", "4294967295", "2147483647", "9223372036854775807")

  # Now read them back using the binary protocol
  echo "Testing numeric results"
  let rdtab = await conn.prepareStatement("select b, i, u, s, u8, s8 from num_tests order by i desc")
  let r2 = await conn.preparedQuery(rdtab)
  assertEq(int, r2.columns.len(), 6, "column count")
  assertEq(int, r2.rows.len(), 5, "row count")
  assertEq(string, r2.columns[0].name, "b")
  assertEq(string, r2.columns[5].name, "s8")

  assertEq(int64,  r2.rows[0][0], 9223372036854775807'i64)
  assertEq(uint64, r2.rows[0][0], 9223372036854775807'u64)
  assertEq(int64,  r2.rows[0][1], 2147483647'i64)
  assertEq(uint64, r2.rows[0][1], 2147483647'u64)
  assertEq(int,    r2.rows[0][1], 2147483647)
  assertEq(uint,   r2.rows[0][1], 2147483647'u)
  assertEq(uint,   r2.rows[0][2], 4294967295'u)
  assertEq(int64,  r2.rows[0][2], 4294967295'i64)
  assertEq(uint64, r2.rows[0][2], 4294967295'u64)
  assertEq(string, r2.rows[0][3], "max")
  assertEq(int,    r2.rows[0][4], 255)
  assertEq(int,    r2.rows[0][5], 127)

  assertEq(int,    r2.rows[1][1], 1)
  assertEq(string, r2.rows[1][3], "one")

  assertEq(int,    r2.rows[2][0], -32768)
  assertEq(int64,  r2.rows[2][0], -32768'i64)
  assertEq(int,    r2.rows[2][1], -32767)
  assertEq(int64,  r2.rows[2][1], -32767'i64)
  assertEq(int,    r2.rows[2][2], 256)
  assertEq(string, r2.rows[2][3], "foo")
  assertEq(int,    r2.rows[2][4], 128)
  assertEq(int,    r2.rows[2][5], -127)
  assertEq(int64,  r2.rows[2][5], -127'i64)

  assertEq(int64,  r2.rows[3][0], 2147483649)
  assertEq(uint,   r2.rows[3][2], 256)

  assertEq(int64,  r2.rows[4][0], ( -9223372036854775807'i64 - 1 ))
  assertEq(int,    r2.rows[4][1], -2147483648)
  assertEq(int,    r2.rows[4][4], 0)
  assertEq(int64,  r2.rows[4][4], 0'i64)

  await conn.closeStatement(rdtab)
  discard await conn.textQuery("drop table `num_tests`")

proc floatTests(conn: Connection): Future[void] {.async.} =
  echo "Setting up table for float tests..."
  discard await conn.textQuery("drop table if exists float_tests")
  discard await conn.textQuery("create table float_tests (s text, a FLOAT, b DOUBLE)")

  echo "Inserting float values"
  # Insert values using the binary protocol
  let insrow = await conn.prepareStatement("insert into `float_tests` (s, a, b) values (?, ?, ?)")
  discard await conn.preparedQuery(insrow, "one", int8(1), 1'f32)
  discard await conn.preparedQuery(insrow, "thou", 0.001'f32, 0.001'f64)
  discard await conn.preparedQuery(insrow, "many", 524288'f64, 1073741824'f32) #swapped
  await conn.closeStatement(insrow)

  # Read them back using the text protocol
  let r1 = await conn.textQuery("select s, a, b from float_tests order by a asc")
  assertEq(int, r1.columns.len(), 3, "column count")
  assertEq(int, r1.rows.len(), 3, "row count")
  assertEq(string, r1.columns[0].name, "s")
  assertEq(string, r1.columns[1].name, "a")

  assertEqrs(r1.rows[0], "thou", "0.001", "0.001")
  assertEqrs(r1.rows[1], "one", "1", "1")
  assertEqrs(r1.rows[2], "many", "524288", "1073741824")

  # Now read them back using the binary protocol
  echo "Reading float values"
  let rdtab = await conn.prepareStatement("select s, a, b from float_tests order by a desc")
  let rdcross = await conn.prepareStatement("select CONCAT(x.s, '+', y.s) as v, x.a + y.a, x.b + y.b from float_tests x, float_tests y where x.s <= y.s order by v")

  let r2 = await conn.preparedQuery(rdtab)
  assertEq(int, r2.rows.len(), 3, "row count")

  doAssert(r2.rows[0][1] == 524288'i32)
  doAssert(r2.rows[0][1] == 524288'i64)
  doAssert(r2.rows[0][1] == 524288'f32)
  doAssert(r2.rows[0][1] == 524288'f64)
  doAssert(r2.rows[0][2] == 1073741824'i32)
  doAssert(r2.rows[0][2] == 1073741824'i64)
  doAssert(r2.rows[0][2] == 1073741824'f32)
  doAssert(r2.rows[0][2] == 1073741824'f64)

  # echo r2.rows[1]
  doAssert(r2.rows[1][1] == 1'u)
  doAssert(r2.rows[1][1] == 1'f32)
  doAssert(r2.rows[1][1] == 1'f64)
  doAssert(r2.rows[1][2] == 1'u)
  doAssert(r2.rows[1][2] == 1'f32)
  doAssert(r2.rows[1][2] == 1'f64)

  let r3 = await conn.preparedQuery(rdcross)
  assertEq(int, r3.rows.len(), 6, "row count")
  assertEq(int, r3.columns.len(), 3, "column count")

  assertEq(string, r3.rows[0][0], "many+many")
  doAssert(r3.rows[0][1] == 1048576'f32)
  doAssert(r3.rows[0][2] == 2147483648'f64)

  assertEq(string, r3.rows[1][0], "many+one")
  doAssert(r3.rows[1][1] == 524289'f32)
  doAssert(r3.rows[1][2] == 1073741825'f64)

  assertEq(string, r3.rows[2][0], "many+thou")
  # Note: [2][1] should be 524288 in single-precision, or 524288.001 in double
  doAssert(r3.rows[2][2] == 1073741824.001'f64)

  assertEq(string, r3.rows[3][0], "one+one")
  # nothing we haven't already tested here

  assertEq(string, r3.rows[4][0], "one+thou")
  assertEq(float32, r3.rows[4][1], 1.001'f32)
  doAssert(r3.rows[4][1] != 1)
  doAssert(r3.rows[4][2] == 1.001'f64)

  await conn.closeStatement(rdtab)
  await conn.closeStatement(rdcross)

  discard await conn.textQuery("drop table `float_tests`")

proc runTests(): Future[void] {.async.} =
  let conn = await connTest()
  await conn.numberTests()
  await conn.floatTests()
  await conn.close()

proc usage(unopt: string = "") =
  if unopt.len > 0:
    stdmsg.writeLine("Unrecognized argument: ", unopt)
  echo "Usage:"
  echo paramStr(0), " [--ssl|--no-ssl] [-v] [-D database] [-h host] [-P portnum] [-u username]"
  echo "\t-D, --database: Perform tests in specified database. (required)"
  echo "\t-h, --host: Connect to server on host. (default: localhost)"
  echo "\t-P, --port: Connect to specified TCP port (default: 3306)"
  echo "\t-u, --username: Connect as specified username (required)"
  echo "\t-p, --password: Provide the specified password"
  echo "\t--ssl, --no-ssl: Enable ssl/tls (default: cleartext)"
  echo "\t--allow-mitm: Disable security checks for SSL"
  echo "\t-v: More verbose output"
  echo "The user must have the ability to create and drop tables in the"
  echo "database, as well as the usual select and insert privileges."
  quit(QuitFailure)

block:
  ## Nim stdlib's parseopt2 doesn't handle standard argument syntax,
  ## so this is a half-assed attempt to do that.
  var ix = 1
  while (ix+1) <= os.paramCount():
    let param = os.paramStr(ix)
    inc(ix)
    case param
    of "--database", "-D":
      database_name = os.paramStr(ix)
      inc(ix)
    of "--host", "-h":
      host_name = os.paramStr(ix)
      inc(ix)
    of "--port", "-P":
      let val = os.paramStr(ix)
      inc(ix)
      if parseInt(val, port, 0) != len(val):
        usage()
    of "--user", "-u":
      user_name = os.paramStr(ix)
      inc(ix)
    of "--password", "-p":
      pass_word = os.paramStr(ix)
      inc(ix)
    of "--ssl":
      ssl = true
    of "--no-ssl":
      ssl = false
    of "--allow-mitm":
      allow_mitm = true
    of "-v", "--verbose":
      verbose = true
    else:
      usage(param)
  if ix != os.paramCount()+1:
    usage()
  if database_name.len == 0 or user_name.len == 0 or port < 1 or port > 65535:
    usage()

waitFor(runTests())
echo "Done"
quit(QuitSuccess)
