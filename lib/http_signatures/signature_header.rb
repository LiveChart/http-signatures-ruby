# frozen_string_literal: true

module HttpSignatures
  class SignatureHeader
    class ParseError < HttpSignatures::Error; end
    class DuplicateParameterError < ParseError; end

    SIGNATURE = "signature"
    KEY_ID = "keyId"
    ALGORITHM = "algorithm"
    HEADERS = "headers"
    CREATED = "created"
    EXPIRES = "expires"

    ALL_PARAMETERS = [
      SIGNATURE,
      KEY_ID,
      ALGORITHM,
      HEADERS,
      CREATED,
      EXPIRES
    ].to_set

    class << self
      def parse(string)
        parts = string.split(",").each_with_object({}) do |segment, result|
          name, value = segment.split("=", 2)

          if result.key?(name)
            # See: https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.2
            raise DuplicateParameterError, "Duplicate parameter: #{name}"
          end

          if !ALL_PARAMETERS.include?(name)
            raise ParseError, "Unparseable segment: #{segment}"
          end

          value_content = value

          case name
          when CREATED, EXPIRES
            # Sub-second precision is not supported.
            # See: https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-3.1
            if !value.match?(%r{\A\d+\z})
              raise ParseError, "Invalid value for #{name}: #{value}"
            end

            value_content = value_content.to_i
          else
            if !value.start_with?('"') || !value.start_with?('"') || value == '""'
              raise ParseError, "Incorrectly formatted value: #{value}"
            end

            value_content = value_content[1..-2]
          end

          result[name] = value_content
        end

        new(
          key_id: parts[KEY_ID],
          algorithm: parts[ALGORITHM],
          covered_content: parts[HEADERS],
          base64_value: parts[SIGNATURE],
          created: parts[CREATED],
          expires: parts[EXPIRES]
        )
      end
    end

    attr_reader :key_id, :algorithm, :covered_content, :base64_value, :expires, :created

    def initialize(key_id:, algorithm:, covered_content:, base64_value:, created: nil, expires: nil)
      @key_id = key_id

      @algorithm =
        case algorithm
        when Algorithm::Base
          algorithm
        when String
          Algorithm.create(algorithm)
        else
          raise ArgumentError, "Invalid Algorithm: #{algorithm}"
        end

      @covered_content =
        case covered_content
        when CoveredContent
          covered_content
        when String
          CoveredContent.from_string(covered_content)
        else
          raise ArgumentError, "Invalid CoveredContent: #{covered_content}"
        end

      @base64_value = base64_value
      @created = created
      @expires = expires
    end

    def to_s
      # TODO: Consider filter_map in Ruby 2.7
      to_h.each_with_object([]) { |(name, value), result|
        next if value.nil?

        case value
        when Integer
          result << %W{#{name}=#{value}}
        else
          result << %W{#{name}="#{value}"}
        end
      }.join(",")
    end

    def to_h
      @_hash ||= {
        KEY_ID => key_id,
        ALGORITHM => algorithm.name,
        HEADERS => covered_content,
        SIGNATURE => base64_value
      }.tap do |hash|
        hash[CREATED] = created if created
        hash[EXPIRES] = expires if expires
      end
    end
  end
end