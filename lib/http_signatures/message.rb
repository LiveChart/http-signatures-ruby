# frozen_string_literal: true

module HttpSignatures
  class Message
    class MissingHeaderError < HttpSignatures::Error
      def initialize(name)
        super("Header '#{name}' not in message")
      end
    end

    attr_reader :path, :verb

    def initialize(path:, headers:, verb:)
      @path = path
      @headers = canonicalized_headers(headers)
      @verb = verb.downcase
    end

    def header?(name)
      @headers.key?(name.downcase)
    end

    def header(name)
      @headers[name.downcase]
    end

    alias [] header

    def header!(name)
      @headers.fetch(name.downcase) { raise MissingHeaderError, name }
    end

    def []=(header_name, value)
      @headers[header_name.downcase] = canonical_header_value(value)
    end

    def headers
      @headers.dup
    end

    def request_target
      "%s %s" % [verb, path]
    end

    class << self
      def from(raw)
        case raw
        when Net::HTTPGenericRequest
          new(
            path: raw.path,
            headers: raw.to_hash,
            verb: raw.method
          )
        when defined?(ActionDispatch) && ActionDispatch::Request
          new(
            path: raw.path,
            headers: raw.headers,
            verb: raw.method
          )
        when defined?(Faraday) && Faraday::Request
          new(
            path: raw.path,
            headers: raw.headers,
            verb: raw.http_method
          )
        else
          raise ArgumentError, "Cannot create a signature message from a #{raw.class}"
        end
      end
    end

    private

    def canonicalized_headers(header_hash)
      header_hash.each_with_object({}) do |(key, value), normalized|
        normalized[key.downcase] = canonical_header_value(value)
      end
    end

    def canonical_header_value(value)
      case value
      when Array
        # Canonicalization of duplicate headers: https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-2.1.1
        value.join(", ")
      else
        value
      end
    end
  end
end
