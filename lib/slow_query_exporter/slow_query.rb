require 'digest/crc64'
require 'socket'

module SlowQueryExporter
  class SlowQuery
    HOSTNAME = Socket.gethostname.freeze

    SPECIAL_PREFIXES = {
      query_string: "_",
      request_time: "_",
      remote_addr: "_",
      timestamp: "",
    }
    PATTERNS = {
      header:   /(^Tcp port:|^Time\s+Id|started with:$)/,
      skip:     /^(# Time: \d+|# Profile_|# No InnoDB statistics|use \w+;)/,
      userhost: /^# User@Host: (\S+)\[\S+\] @\s*(\S*)\s*\[(\S*)\]/,
      schema:   /^# Schema: (\w*)\s+Last_errno: (\d+)\s+Killed: (\d+)/,
      qtime:    /^# Query_time: (\S+)\s+Lock_time: (\S+)\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)\s+Rows_affected: (\d+)/,
      bytes:    /^# Bytes_sent: (\d+)\s+Tmp_tables: (\d+)\s+Tmp_disk_tables: (\d+)\s+Tmp_table_sizes: (\d+)/,
      trxid:    /^# InnoDB_trx_id: (\S+)/,
      qchit:    /^# QC_Hit: (\w+)\s+Full_scan: (\w+)\s+Full_join: (\w+)/,
      filesort: /^# Filesort: (\w+)\s+Filesort_on_disk: (\w+)\s+Merge_passes: (\d+)/,
      innoio:   /^#\s+InnoDB_IO_r_ops: (\d+)\s+InnoDB_IO_r_bytes: (\d+)\s+InnoDB_IO_r_wait: (\S+)/,
      innowait: /^#\s+InnoDB_rec_lock_wait: (\S+)\s+InnoDB_queue_wait: (\S+)/,
      innopage: /^#\s+InnoDB_pages_distinct: (\d+)/,
      time:     /^SET timestamp=(\d+)/,
      query:    /^(DELETE|EXPLAIN|INSERT|REPLACE|SELECT|SHOW|UPDATE|COMMIT|SET|DESC(?:RIBE)?|# administrator)\b/i,
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
        attributes[:remote_addr] = $3.empty? ? $2 : $3
      when PATTERNS[:schema]
        attributes[:schema] = $1
        attributes[:errno] = $2.to_i
        attributes[:killed] = $3.to_i > 0
      when PATTERNS[:qtime]
        attributes[:request_time] = $1.to_f
        attributes[:lock_time] = $2.to_f
        attributes[:rows_sent] = $3.to_i
        attributes[:rows_examined] = $4.to_i
        attributes[:rows_affected] = $5.to_i
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
      if attributes[:query_string] =~ /;$/
        attributes[:query_string] = normalized_query(attributes[:query_string])
        @done = true
      end
    end

    def gelf_attributes
      fingerprint = Digest::CRC64.hexdigest(attributes[:query_string]).upcase
      gelf_attrs = {
        "version" => "1.1",
        "short_message" => sprintf("Slow query %s on %s: %.2f seconds", fingerprint, HOSTNAME, attributes[:request_time]),
        "host" => HOSTNAME,
        "_type" => "mysql-slow",
        "_mysql_fingerprint" => fingerprint,
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
    def normalized_query(sql)
      return "mysqldump" if sql =~ %r{\ASELECT /\*!40001 SQL_NO_CACHE \*/ \* FROM `}
      return "percona-toolkit" if sql =~ %r{/\*\w+\.\w+:[0-9]/[0-9]\*/}
      return sql if sql =~ /\Aadministrator command: /i
      return $1.downcase if sql =~ /\A\s*(call\s+\S+)\(/i

      # Truncate multi-value INSERT statements
      sql = $1 if sql =~ /\A((?:INSERT|REPLACE)(?: IGNORE)?\s+INTO.+?VALUES\s*\(.*?\))\s*,\s*\(/im

      sql.gsub!(%r{/\*[^!].*?\*/}m, "")                     # Strip multi-line comments
      sql.gsub!(%r{(?:--|#)[^'"\r\n]*(?=[\r\n]|\Z)}m, "")   # Strip single-line comments
      return "use ?" if sql =~ /\Ause \S+\Z/i

      # Replace quoted strings with "?"
      sql.gsub!(/\\["']/, "")
      sql.gsub!(/".*?"/, "?")
      sql.gsub!(/'.*?'/, "?")

      sql.downcase!
      sql.gsub!(/\bfalse\b|\btrue\b/, "?")      # Replace boolean values with "?"
      sql.gsub!(/[0-9+-][0-9a-f.xb+-]*/, "?")   # Replace numbers with "?"
      sql.gsub!(/[xb.+-]\?/, "?")               # Strip number prefixes

      sql.gsub!(/\bnull\b/, "?")   # Replace NULLs with "?"

      sql.gsub!(/\b(in|values?)(?:[\s,]*\([\s?,]*\))+/, "\\1(?+)")                   # Collapse IN and VALUES lists
      sql.gsub!(/\b(select\s.*?)(?:(\sunion(?:\sall)?)\s\1)+/, "\\1 /*repeat$2*/")   # Collapse UNIONs
      sql.sub!(/\blimit \?(?:, ?\?| offset \?)?/, "limit ?")   # LIMITs and OFFSETs
      sql.gsub(/\border by (.+?)\s+asc/, "order by \\1")       # Remove extraneous ASCs from ORDER BYs
    end

    # Remove leading/trailing whitespace and compress all other runs of whitespace into a single space.
    def compress(str)
      str.strip.tr_s(" \n\t\r\f", " ")
    end
  end
end
