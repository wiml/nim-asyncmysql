Non-blocking mysql client for Nim
=================================

This is a scratch-written pure-[Nim][nimlang] implementation of the client
side of the MySQL database protocol (also compatible
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

Other than ordinary queries, it does not support various
other commands that might be useful. It doesn't support
old versions of the server (pre-4.1) or probably several other things.
It was primarily an exercise in learning Nim.

Notes and Deficiencies
----------------------

For practical asynchronous use, some kind of turnstile mechanism needs
to exist in order to prevent different requests from stomping on
each other. It might make sense to combine this with some kind of
transaction support.

The API presented by this module is very specific to MySQL. A more
generic async DB API would be nice.

Long packets (more than 2^24-1 bytes) are not handled correctly.

The compressed protocol is not supported--- I'm not sure if this is
actually a deficiency. As a workaround, SSL with a null cipher and
compression could be used.

For password authentication to work, you need a patched version of
Nim's openssl module which provides access to the EVP_MD API in libcrypto.
A patch is in openssl_evp.patch, but it is perhaps too ad-hoc for
integration into Nim.

For SSL connections to work, you need a patched version of Nim's
asyncnet module which properly handshakes a ssl-wrapped socket.
You can find that here, until/unless it is accepted into
mainline Nim: https://github.com/wiml/Nim/tree/starttls

For local (unix-domain) connections to work, you would need to extend Nim's
socket modules to support those.

### Binary protocol

Floats and doubles are unsupported (but not hard to support). Likewise
dates and times.

Integer conversions between the local data types and the wire protocol
might not be correct in all circumstances, especially if Nim's int is
32 bits wide.

The protocol allows streaming large values to the server (if, for example,
you are inserting a large BLOB) and this could be implemented elegantly
as parameter that lazily generates strings.

Cursors, FETCH, and the like are not implemented.

[nimlang]: http://nim-lang.org/
