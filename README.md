# slow_query_exporter

A daemon which monitors a MySQL slow query log and sends every entry it
sees to Graylog.

It sends slow queries to Graylog via UDP in GELF format. The key names are
somewhat idiosyncratic to the particular corporate environment it hails
from, so you might want to change them. It's only been tested against
Percona Server 5.6, not stock MySQL; I'm uncertain if there are any
substantial differences in the slow query log format between them.

## Usage

```
Usage: slow_query_exporter [-fv] [-d delay] [-h host] [-p port] /path/to/slow_query.log
    -d, --delay SECONDS    An interval to pause after each GELF message, in (possibly fractional) seconds
    -f, --foreground       Don't daemonize on startup
    -?, --help             Display this help text
    -h, --host HOST        The GELF host
    -p, --port PORT        The GELF UDP port
    -v, --[no-]verbose     Print entries to stdout as they're parsed
        --version          Display application version information
```
