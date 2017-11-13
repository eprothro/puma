require 'puma/util'
require 'puma/minissl'

module Puma
  class Reactor
    DefaultSleepFor = 5

    def initialize(server, app_pool)
      @server = server
      @events = server.events
      @app_pool = app_pool

      @mutex = Mutex.new
      @ready, @trigger = Puma::Util.pipe
      @input = []
      @sleep_for = DefaultSleepFor
      @timeouts = []

      @sockets = [@ready]
    end

    private

    def run_internal
      sockets = @sockets

      while true
        begin
          ready = IO.select sockets, nil, nil, @sleep_for
        rescue IOError => e
          Thread.current.purge_interrupt_queue if Thread.current.respond_to? :purge_interrupt_queue
          if sockets.any? { |socket| socket.closed? }
            STDERR.puts "Error in select: #{e.message} (#{e.class})"
            STDERR.puts e.backtrace
            sockets.each do |socket|
              @mutex.synchronize do
                remove(socket) if socket.closed?
              end
            end
            retry
          else
            raise
          end
        end

        if ready and reads = ready[0]
          reads.each do |c|
            if c == @ready
              @mutex.synchronize do
                case @ready.read(1)
                when "*"
                  sockets.concat(@input)
                  @input.clear
                when "c"
                  sockets.each do |s|
                    if s == @ready
                      # carry on
                    else
                      s.close
                      remove(socket)
                    end
                  end
                when "!"
                  return
                end
              end
            else
              # We have to be sure to remove it from the timeout
              # list or we'll accidentally close the socket when
              # it's in use!
              if c.timeout_at
                @mutex.synchronize do
                  @timeouts.delete c
                end
              end

              begin
                if c.try_to_finish
                  @app_pool << c
                  remove(c)
                end

              # Don't report these to the lowlevel_error handler, otherwise
              # will be flooding them with errors when persistent connections
              # are closed.
              rescue ConnectionError
                c.write_500
                c.close

                remove(c)

              # SSL handshake failure
              rescue MiniSSL::SSLError => e
                @server.lowlevel_error(e, c.env)

                ssl_socket = c.io
                addr = ssl_socket.peeraddr.last
                cert = ssl_socket.peercert

                c.close
                remove(c)

                @events.ssl_error @server, addr, cert, e

              # The client doesn't know HTTP well
              rescue HttpParserError => e
                @server.lowlevel_error(e, c.env)

                c.write_400
                c.close

                remove(c)

                @events.parse_error @server, c.env, e
              rescue StandardError => e
                @server.lowlevel_error(e, c.env)

                c.write_500
                c.close

                remove(c)
              end
            end
          end
        end

        unless @timeouts.empty?
          @mutex.synchronize do
            now = Time.now

            while @timeouts.first.timeout_at < now
              c = @timeouts.shift
              c.write_408 if c.in_data_phase
              c.close
              remove(c)

              break if @timeouts.empty?
            end

            calculate_sleep
          end
        end
      end
    end

    # must have mutex locked when calling
    def remove(c)
      if @sockets.delete(c)
        # this is a total hack, not thread safe
        # and only for spike/validation purposes!
        @app_pool.instance_variable_get(:@not_full).signal
      end
    end

    public

    def run
      run_internal
    ensure
      @trigger.close
      @ready.close
    end

    def run_in_thread
      @thread = Thread.new do
        begin
          run_internal
        rescue StandardError => e
          STDERR.puts "Error in reactor loop escaped: #{e.message} (#{e.class})"
          STDERR.puts e.backtrace
          retry
        ensure
          @trigger.close
          @ready.close
        end
      end
    end

    def calculate_sleep
      if @timeouts.empty?
        @sleep_for = DefaultSleepFor
      else
        diff = @timeouts.first.timeout_at.to_f - Time.now.to_f

        if diff < 0.0
          @sleep_for = 0
        else
          @sleep_for = diff
        end
      end
    end

    def add(c)
      @mutex.synchronize do
        @input << c
        @trigger << "*"

        if c.timeout_at
          @timeouts << c
          @timeouts.sort! { |a,b| a.timeout_at <=> b.timeout_at }

          calculate_sleep
        end
      end
    end

    # The number of connections being watched
    def size
      @mutex.synchronize do
        count = @sockets.size
        count -= 1 if @sockets.include?(@ready)
        count
      end
    end

    # Close all watched sockets and clear them from being watched
    def clear!
      begin
        @trigger << "c"
      rescue IOError
        Thread.current.purge_interrupt_queue if Thread.current.respond_to? :purge_interrupt_queue
      end
    end

    def shutdown
      begin
        @trigger << "!"
      rescue IOError
        Thread.current.purge_interrupt_queue if Thread.current.respond_to? :purge_interrupt_queue
      end

      @thread.join
    end
  end
end
