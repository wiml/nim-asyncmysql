Non-blocking mysql client for Nim
=================================

This is a scratch-written pure-[Nim][nimlang] implementation of the client
side of the MySQL database protocol (should also be compatible
with MariaDB, etc.). It's based on the `asyncdispatch` and
`asyncnet` modules and should be a fully non-blocking, asynchronous
library.

The library implements both the
"[text protocol](https://dev.mysql.com/doc/internals/en/com-query.html)"
(send a simple string query, get back results as strings)
and the
"[binary protocol](https://dev.mysql.com/doc/internals/en/prepared-statements.html)"
(get a prepared statement handle from a string with
placeholders; send a set of value bindings, get back results
as various datatypes approximating what the server is
using).

It currently does not support any kind of authentication, SSL,
or various other commands that might be useful. It doesn't support
old versions of the server (pre-4.1) or probably several other things.
It is primarily an exercise in learning Nim.

Notes and Deficiencies
----------------------

For practical asynchronous use, some kind of turnstile mechanism needs
to exist in order to prevent different requests from stomping on
each other. It might make sense to combine this with some kind of
transaction support.

The API presented by this module is very specific to MySQL. A more
generic async DB API would be nice.

### Binary protocol

Floats and doubles are unsupported (but not hard to support). Likewise
dates and times.

Integer conversions between the local data types and the wire protocol
might not be correct in all circumstances, especially if Nim's int is
32 bits wide.

The protocol allows streaming large values to the server (if, for example,
you are inserting a large BLOB) and this could be implemented elegantly
as parameter that lazily generates strings.

[nimlang]: http://nim-lang.org/
