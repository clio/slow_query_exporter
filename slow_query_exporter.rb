#!/usr/bin/env ruby

require 'daemons'
require 'digest/crc64'
require 'gelf'
require 'optparse'
require 'syslog'

RUN_DIRECTORY = "/var/run/slow_query_exporter"
PROGRESS_FILE = "#{RUN_DIRECTORY}/last_timestamp"

class QueryParser
  def initialize
    @buffer = ""
    @parsed = []
    reset!
  end

  def reset!
    @query = SlowQuery.new
  end

  def parse_line(line)
    @query.parse_line(line)
    if @query.done?
      @parsed << @query
      @query = SlowQuery.new
    end
  rescue => e
    Syslog.err(e.message)
    reset!
  end

  def pop_finished_query
    @parsed.pop
  end
end

class SlowQuery
  SPECIAL_PREFIXES = {
    query_string: "_",
    request_time: "_",
    host: "_",
    timestamp: "",
  }
  PATTERNS = {
    header:   /(^Tcp port:|^Time\s+Id|started with:$)/,
    skip:     /^(# Time: \d+|# Profile_|use \w+;)/,
    userhost: /^# User@Host: (\S+)\[\S+\] @\s+\[(\S+)\]/,
    thread:   /^# Thread_id: (\d+)\s+Schema: (\w+)\s+Last_errno: (\d+)\s+Killed: (\d+)/,
    qtime:    /^# Query_time: (\S+)\s+Lock_time: (\S+)\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)\s+Rows_affected: (\d+)\s+Rows_read: (\d+)/,
    bytes:    /^# Bytes_sent: (\d+)\s+Tmp_tables: (\d+)\s+Tmp_disk_tables: (\d+)\s+Tmp_table_sizes: (\d+)/,
    trxid:    /^# InnoDB_trx_id: (\S+)/,
    qchit:    /^# QC_Hit: (\w+)\s+Full_scan: (\w+)\s+Full_join: (\w+)/,
    filesort: /^# Filesort: (\w+)\s+Filesort_on_disk: (\w+)\s+Merge_passes: (\d+)/,
    innoio:   /^#\s+InnoDB_IO_r_ops: (\d+)\s+InnoDB_IO_r_bytes: (\d+)\s+InnoDB_IO_r_wait: (\S+)/,
    innowait: /^#\s+InnoDB_rec_lock_wait: (\S+)\s+InnoDB_queue_wait: (\S+)/,
    innopage: /^#\s+InnoDB_pages_distinct: (\d+)/,
    time:     /^SET timestamp=(\d+)/,
    query:    /^(SELECT|INSERT|UPDATE|DELETE)\b/,
  }

  attr_accessor :attributes

  def initialize
    @attributes = {query_string: ""}
    @done = false
  end

  def parse_line(line)
    return if line =~ PATTERNS[:header] || line =~ PATTERNS[:skip]

    case line
    when PATTERNS[:userhost]
      attributes[:user] = $1
      attributes[:host] = $2
    when PATTERNS[:thread]
      attributes[:thread_id] = $1.to_i
      attributes[:schema] = $2
      attributes[:errno] = $3.to_i
      attributes[:killed] = $4.to_i > 0
    when PATTERNS[:qtime]
      attributes[:request_time] = $1.to_f
      attributes[:lock_time] = $2.to_f
      attributes[:rows_sent] = $3.to_i
      attributes[:rows_examined] = $4.to_i
      attributes[:rows_affected] = $5.to_i
      attributes[:rows_read] = $6.to_i
    when PATTERNS[:bytes]
      attributes[:bytes_sent] = $1.to_i
      attributes[:tmp_tables] = $2.to_i
      attributes[:tmp_disk_tables] = $3.to_i
      attributes[:tmp_table_sizes] = $4.to_i
    when PATTERNS[:trxid]
      attributes[:transaction_id] = $1
    when PATTERNS[:qchit]
      attributes[:used_query_cache] = $1 == "Yes"
      attributes[:full_scan] = $2 == "Yes"
      attributes[:full_join] = $3 == "Yes"
    when PATTERNS[:filesort]
      attributes[:filesort] = $1 == "Yes"
      attributes[:filesort_on_disk] = $2 == "Yes"
      attributes[:merge_passes] = $3.to_i
    when PATTERNS[:innoio]
      attributes[:io_read_ops] = $1.to_i
      attributes[:io_read_bytes] = $2.to_i
      attributes[:io_read_wait] = $3.to_f
    when PATTERNS[:innowait]
      attributes[:io_lock_wait] = $1.to_f
      attributes[:io_queue_wait] = $2.to_f
    when PATTERNS[:innopage]
      attributes[:io_distinct_pages] = $1.to_i
    when PATTERNS[:time]
      attributes[:timestamp] = $1.to_i
    when PATTERNS[:query]
      append_line(line)
    else
      if !attributes[:query_string].empty?
        append_line(line)
      else
        raise ArgumentError.new("Unparseable slow query log line: #{line}")
      end
    end
  end

  def done?
    @done
  end

  def timestamp
    attributes[:timestamp]
  end

  def append_line(line)
    line = compress(line)
    line = " " << line if !attributes[:query_string].empty?
    attributes[:query_string] += line
    @done = true if attributes[:query_string] =~ /;$/
  end

  def gelf_attributes
    fingerprint = Digest::CRC64.hexdigest(normalized_query).upcase
    gelf_attrs = {
      "version" => "1.1",
      "short_message" => sprintf("Slow query %s on %s: %.2f seconds", fingerprint, attributes[:host], attributes[:request_time]),
      "_type" => "mysql-slow",
      "_fingerprint" => fingerprint,
    }
    attributes.each do |key, val|
      prefix = SPECIAL_PREFIXES.fetch(key, "_mysql_")
      gelf_attrs[prefix + key.to_s] = val
    end
    gelf_attrs
  end

  private

  # This is just a straight port of pt-query-digest's Perl fingerprint function.
  # The ugly regexps aren't my fault! :-D
  def normalized_query
    q = attributes[:query_string].dup
    return "mysqldump" if q =~ %r{\ASELECT /\*!40001 SQL_NO_CACHE \*/ \* FROM `}
    return "percona-toolkit" if q =~ %r{/\*\w+\.\w+:[0-9]/[0-9]\*/}
    return q if q =~ /\Aadministrator command: /i
    return $1.downcase if q =~ /\A\s*(call\s+\S+)\(/i

    # Truncate multi-value INSERT statements
    q = $1 if q =~ /\A((?:INSERT|REPLACE)(?: IGNORE)?\s+INTO.+?VALUES\s*\(.*?\))\s*,\s*\(/im

    q.gsub!(%r{/\*[^!].*?\*/}m, "")                     # Strip multi-line comments
    q.gsub!(%r{(?:--|#)[^'"\r\n]*(?=[\r\n]|\Z)}m, "")   # Strip single-line comments
    return "use ?" if q =~ /\Ause \S+\Z/i

    # Replace quoted strings with "?"
    q.gsub!(/\\["']/, "")
    q.gsub!(/".*?"/, "?")
    q.gsub!(/'.*?'/, "?")

    q.downcase!
    q.gsub!(/\bfalse\b|\btrue\b/, "?")      # Replace boolean values with "?"
    q.gsub!(/[0-9+-][0-9a-f.xb+-]*/, "?")   # Replace numbers with "?"
    q.gsub!(/[xb.+-]\?/, "?")               # Strip number prefixes

    q.gsub!(/\bnull\b/, "?")   # Replace NULLs with "?"

    q.gsub!(/\b(in|values?)(?:[\s,]*\([\s?,]*\))+/, "\\1(?+)")                   # Collapse IN and VALUES lists
    q.gsub!(/\b(select\s.*?)(?:(\sunion(?:\sall)?)\s\1)+/, "\\1 /*repeat$2*/")   # Collapse UNIONs
    q.sub!(/\blimit \?(?:, ?\?| offset \?)?/, "limit ?")   # LIMITs and OFFSETs
    q.gsub(/\border by (.+?)\s+asc/, "order by \\1")       # Remove extraneous ASCs from ORDER BYs
  end

  # Remove leading/trailing whitespace and compress all other runs of whitespace into a single space.
  def compress(str)
    str.strip.tr_s(" \n\t\r\f", " ")
  end
end


$graylog_host = "localhost"
$graylog_port = 12201
$delay = 0.1
$verbose = false
$foreground = false

HELP_TEXT = "Usage: slow_query_exporter.rb [-fv] [-d delay] [-h host] [-p port] slow_query.log
Options:
    -h, --host         The Graylog host
    -p, --port         The Graylog port
    -d, --delay        An interval to pause after each GELF message, in (possibly fractional) seconds
    -v, --verbose      Print entries to stdout as they're parsed
    -f, --foreground   Don't daemonize on startup
    -?, --help         Display this help text
"

OptionParser.new do |opts|
  opts.banner = HELP_TEXT

  opts.on("-h", "--host") { |host| $graylog_host = host }
  opts.on("-p", "--port") { |port| $graylog_port = port }
  opts.on("-d", "--delay") { |delay| $delay = delay.to_f }
  opts.on("-v", "--verbose") { $verbose = true }
  opts.on("-f", "--foreground") { $foreground = true }
  opts.on("-?", "--help") do
    $stderr.puts(HELP_TEXT)
    exit
  end
end.parse!

if ARGV.empty?
  $stderr.puts(HELP_TEXT)
  exit 1
end

Daemons.daemonize(dir_mode: :normal, dir: RUN_DIRECTORY) unless $foreground
Syslog.open("slow_query_exporter", Syslog::LOG_PID | Syslog::LOG_PERROR, Syslog::LOG_DAEMON)
last_timestamp = begin
                   IO.read(PROGRESS_FILE).to_i
                 rescue Errno::ENOENT
                   0
                 end

# We touch the logfile to make sure it exists before we start. Otherwise, "tail -F" will die.
logfile = ARGV[0]
File.open(logfile, "a") {}

gelf = GELF::Notifier.new($graylog_host, $graylog_port, "WAN")
parser = QueryParser.new

begin
  tail = IO.popen(["tail", "-F", "-n", "+0", logfile])
  tail.each_line do |line|
    parser.parse_line(line)
    query = parser.pop_finished_query
    if query && query.timestamp >= last_timestamp
      last_timestamp = query.timestamp
      File.open(PROGRESS_FILE, "w") { |f| f.puts(last_timestamp) }

      puts query.gelf_attributes.inspect, "\n" if $verbose
      gelf.notify!(query.gelf_attributes)
      sleep $delay    # avoids swamping the Graylog server
    end
  end

ensure
  Process.kill("INT", tail.pid) if tail
end
