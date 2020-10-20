# frozen_string_literal: true

module HttpSignatures
  class Message
    class MissingHeaderError < StandardError
      def initialize(name)
        super("Header '#{name}' not in message")
      end
    end

    attr_reader :path, :headers, :verb

    def initialize(path:, headers:, verb:)
      @path = path
      @headers = headers
      @verb = verb.downcase
    end

    def header?(name)
      headers.key?(name.downcase)
    end

    def header(name)
      headers[name.downcase]
    end

    alias [] header

    def header!(name)
      headers.fetch(name.downcase) { raise MissingHeaderError, name }
    end

    def []=(header_name, value)
      headers[header_name.downcase] = value
    end

    def request_target
      "%s %s" % [verb, path]
    end

    class << self
      def from(raw)
        case raw
        when Net::HTTPGenericRequest
          # Canonicalization of duplicate headers: https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-2.1.1
          new(
            path: raw.path,
            headers: raw.to_hash.transform_values! { |value| value.join(", ") },
            verb: raw.method
          )
        when defined?(ActionDispatch) && ActionDispatch::Request
          new(
            path: raw.path,
            headers: raw.to_hash,
            verb: raw.method
          )
        else
          raise ArgumentError, "Cannot create a signature message from a #{raw.class}"
        end
      end
    end
  end
end
