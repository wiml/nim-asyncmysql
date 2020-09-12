{.experimental: "notnil".}

import asyncmysql, asyncdispatch, asyncnet
from nativesockets import AF_INET, SOCK_STREAM

import net

proc printResultSet[T](resultSet: ResultSet[T]) =
  if resultSet.columns.len > 0:
    for ix in low(resultSet.columns) .. high(resultSet.columns):
      stdmsg.writeLine("Column ", ix, " - ", $(resultSet.columns[ix].column_type))
      stdmsg.writeLine("    Name: ", resultSet.columns[ix].name)
      stdmsg.writeLine("    orig: ", resultSet.columns[ix].catalog, ".", resultSet.columns[ix].schema, ".", resultSet.columns[ix].orig_table, ".", resultSet.columns[ix].orig_name)
      stdmsg.writeLine("          length=", int(resultSet.columns[ix].length))
      stdmsg.writeLine("")
    for row in resultSet.rows:
      for ix in low(row)..high(row):
        stdmsg.write(resultSet.columns[ix].name)
        if isNil(row[ix]):
          stdmsg.writeLine(" is NULL")
        else:
          stdmsg.writeLine(" = ", row[ix])
      stdmsg.writeLine("")
  stdmsg.writeLine(resultSet.status.affected_rows, " rows affected")
  stdmsg.writeLine("last_insert_id = ", resultSet.status.last_insert_id)
  stdmsg.writeLine(resultSet.status.warning_count, " warnings")
  stdmsg.writeLine("status: ", $(resultSet.status.status_flags))
  if len(resultSet.status.info) > 0:
    stdmsg.writeLine("Info: ", resultSet.status.info)

proc demoTextQuery(conn: Connection, query: string) {.async.} =
  let res = await conn.textQuery(query)
  printResultSet(res)

proc demoPreparedStatement(conn: Connection) {.async.} =
  let stmt = await conn.prepareStatement("select *, ( ? + 1 ) from user u where u.user = ?")
  let rslt = await conn.preparedQuery(stmt, 42, "root")
  printResultSet(rslt)
  await conn.closeStatement(stmt)

proc blah() {. async .} =
  let sockn = newAsyncSocket(AF_INET, SOCK_STREAM)
  var sock: AsyncSocket not nil
  if sockn.isNil:
    raise newException(ValueError, "nil socket")
  else:
    sock = sockn
  await connect(sock, "db4free.net", Port(3306))
  stdmsg.writeLine("(socket connection established)")
  when defined(ssl):
    let conn = await establishConnection(sock, "test", database = "testdb", password = "test_pass", sslHostname = "db4free.net", ssl = newContext(verifyMode = CVerifyPeer))
  else:
    let conn = await establishConnection(sock, "test", database = "testdb", password = "test_pass")
  stdmsg.writeLine("(mysql session established)")
  await conn.demoTextQuery("select * from mysql.user")
  await conn.demoPreparedStatement()
  #await conn.demoTextQuery("show session variables like '%ssl%'");
  await conn.demoTextQuery("show session variables like '%version%'");

proc foof() =
  let fut = blah()
  stdmsg.writeLine("starting loop")
  waitFor(fut)
  stdmsg.writeLine("done")

foof()

