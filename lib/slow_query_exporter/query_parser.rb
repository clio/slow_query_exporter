module SlowQueryExporter
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
end
