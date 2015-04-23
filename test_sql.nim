import asyncmysql, asyncdispatch, asyncnet, os, parseutils
from rawsockets import AF_INET, SOCK_STREAM

import net

var database_name: string
var port: int = 3306
var host_name: string = "localhost"
var user_name: string
var pass_word: string
var ssl: bool = false
var verbose: bool = false

proc doTCPConnect(dbn: string = nil): Future[Connection] {.async.} =
  let sock = newAsyncSocket(AF_INET, SOCK_STREAM)
  await connect(sock, host_name, Port(port))
  if ssl:
    let ctx = newContext(verifyMode = CVerifyPeer)
    return await establishConnection(sock, user_name, database=dbn, password = pass_word, ssl=ctx)
  else:
    return await establishConnection(sock, user_name, database=dbn, password = pass_word)

proc getCurrentDatabase(conn: Connection): Future[string] {.async.} =
  let rslt = await conn.textQuery("select database()")
  doAssert(len(rslt.columns) == 1, "wrong number of result columns")
  doAssert(len(rslt.rows) == 1, "wrong number of result rows")
  return rslt.rows[0][0]

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
  echo "Checking TIDs"
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
  echo "Closing second connection"
  await conn2.close()
  return conn1

proc runTests(): Future[void] {.async.} =
  let conn = await connTest()
  await conn.close()

proc usage(unopt: string = nil) =
  if not isNil(unopt):
    stdmsg.writeln("Unrecognized argument: ", unopt)
  echo "Usage:"
  echo paramStr(0), " [-D database] [-h host] [-P portnum] [-u username] [--ssl|--no-ssl]"
  echo "\t-D, --database: Perform tests in specified database. (required)"
  echo "\t-h, --host: Connect to server on host. (default: localhost)"
  echo "\t-P, --port: Connect to specified TCP port (default: 3306)"
  echo "\t-u, --username: Connect as specified username (required)"
  echo "\t--ssl, --no-ssl: Enable ssl/tls (default: cleartext)"
  echo "\t-v: More verbose output"
  echo "The user must have the ability to create and drop tables in the"
  echo "database, as well as the usual select and insert privileges."
  quit(QuitFailure)

block:
  ## Nim stdlib's parseopt2 doesn't handle standard argument syntax,
  ## so this is a half-assed attempt to do that. This doesn't handle
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
    of "-v", "--verbose":
      verbose = true
    else:
      usage(param)
  if ix != os.paramCount()+1:
    usage()
  if isNil(database_name) or isNil(user_name) or port < 1 or port > 65535:
    usage()

waitFor(runTests())
echo "Done"
