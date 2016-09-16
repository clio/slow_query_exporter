# slow_query_exporter

A daemon which monitors a MySQL slow query log and sends every entry it
sees to Graylog.

It sends slow queries to Graylog via UDP in GELF format. The key names are
somewhat idiosyncratic to the particular corporate environment it hails
from, so you might want to change them. It's only been tested against
Percona Server, not stock MySQL; I'm uncertain if there are any substantial
differences in the slow query log format between them.

## Usage

```
Usage: slow_query_exporter.rb [-v] [-h host] [-p port] slow_query.log
Options:
    -h, --host      The Graylog host
    -p, --port      The Graylog port
    -v, --verbose   Print entries to stdout as they're parsed
    -?, --help      Display this help text
```
