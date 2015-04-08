import asyncmysql, asyncdispatch, asyncnet
from rawsockets import AF_INET, SOCK_STREAM

proc printResultSet[T](resultSet: ResultSet[T]) =
  if not isNil(resultSet.columns) and resultSet.columns.len > 0:
    for ix in low(resultSet.columns) .. high(resultSet.columns):
      stdmsg.writeln("Column ", ix, " - ", $(resultSet.columns[ix].column_type))
      stdmsg.writeln("    Name: ", resultSet.columns[ix].name)
      stdmsg.writeln("    orig: ", resultSet.columns[ix].catalog, ".", resultSet.columns[ix].schema, ".", resultSet.columns[ix].orig_table, ".", resultSet.columns[ix].orig_name)
      stdmsg.writeln("          length=", int(resultSet.columns[ix].length))
      stdmsg.writeln("")
    for row in resultSet.rows:
      for ix in low(row)..high(row):
        stdmsg.write(resultSet.columns[ix].name)
        if isNil(row[ix]):
          stdmsg.writeln(" is NULL")
        else:
          stdmsg.writeln(" = ", row[ix])
      stdmsg.writeln("")
  stdmsg.writeln(resultSet.status.affected_rows, " rows affected")
  stdmsg.writeln("last_insert_id = ", resultSet.status.last_insert_id)
  stdmsg.writeln(resultSet.status.warning_count, " warnings")
  stdmsg.writeln("status: ", $(resultSet.status.status_flags))
  if not isNil(resultSet.status.info) and len(resultSet.status.info) > 0:
    stdmsg.writeln("Info: ", resultSet.status.info)

proc demoTextQuery(conn: Connection, query: string) {.async.} =
  let res = await conn.textQuery(query)
  printResultSet(res)

proc demoPreparedStatement(conn: Connection) {.async.} =
  let stmt = await conn.prepareStatement("select *, ( ? + 1 ) from user u where u.user = ?")
  let rslt = await conn.preparedQuery(stmt, 42, "root")
  printResultSet(rslt)

proc blah() {. async .} =
  let sock = newAsyncSocket(AF_INET, SOCK_STREAM)
  await connect(sock, "localhost", Port(3306))
  stdmsg.writeln("(socket connection established)")
  let conn = await establishUnauthenticatedConnection(sock, "root", database = "mysql")
  stdmsg.writeln("(mysql session established)")
  await conn.demoTextQuery("select * from mysql.user")
  await conn.demoPreparedStatement()

proc foof() =
  let fut = blah()
  stdmsg.writeln("starting loop")
  waitFor(fut)
  stdmsg.writeln("done")

foof()
