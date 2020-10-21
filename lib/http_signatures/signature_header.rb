# frozen_string_literal: true

module HttpSignatures
  class SignatureHeader
    class Error < HttpSignatures::Error; end
    class ParseError < Error; end
    class ParameterError < ParseError; end

    class UnsupportedAlgorithmError < Error
      def initialize(name)
        super("Unsupported algorithm: #{name}")
      end
    end

    SEPARATOR = ","
    KEY_VALUE_SEPARATOR = "="

    SIGNATURE = "signature"
    KEY_ID = "keyId"
    ALGORITHM = "algorithm"
    HEADERS = "headers"
    CREATED = "created"
    EXPIRES = "expires"

    ALL_PARAMETERS = [
      KEY_ID,
      SIGNATURE,
      ALGORITHM,
      HEADERS,
      CREATED,
      EXPIRES
    ].to_set.freeze

    REQUIRED_PARAMETERS = [KEY_ID, SIGNATURE].freeze

    DEFAULTS = {
      ALGORITHM => Algorithm::HS2019,
      HEADERS => CoveredContent::CREATED
    }.freeze

    class << self
      def parse(string)
        # We don't use a hash of defaults due to duplicate parameter checking.
        parts = string.split(SEPARATOR).each_with_object({}) do |segment, result|
          name, value = segment.split(KEY_VALUE_SEPARATOR, 2)

          if result.key?(name)
            # See: https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.2
            raise ParseError, "Duplicate parameter: #{name}"
          end

          # Should we really raise an error or just ignore the parameter?
          # See: https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.2
          if !ALL_PARAMETERS.include?(name)
            raise ParseError, "Unparseable segment: #{segment}"
          end

          value_content = value

          case name
          when CREATED, EXPIRES
            # Sub-second precision is not supported.
            # See: https://tools.ietf.org/html/draft-ietf-httpbis-message-signatures-00#section-3.1
            if !value.match?(%r{\A\d+\z})
              raise ParseError, "Invalid value for #{name} (must be an integer): #{value}"
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

        REQUIRED_PARAMETERS.each do |required_parameter|
          unless parts.key?(required_parameter)
            raise ParseError, "Missing required parameter: #{required_parameter}"
          end
        end

        new(
          key_id: parts[KEY_ID],
          algorithm: parts.fetch(ALGORITHM, DEFAULTS[ALGORITHM]),
          covered_content: parts.fetch(HEADERS, DEFAULTS[HEADERS]),
          base64_value: parts[SIGNATURE],
          created: parts[CREATED],
          expires: parts[EXPIRES]
        )
      end
    end

    attr_reader :key_id, :algorithm, :covered_content, :base64_value, :expires, :created

    def initialize(
      key_id:,
      algorithm: DEFAULTS[ALGORITHM],
      covered_content: DEFAULTS[HEADERS],
      base64_value:,
      created: nil,
      expires: nil
    )
      @key_id = key_id
      @algorithm = algorithm

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

      assert_valid_values!
    end

    def to_s
      # TODO: Consider filter_map in Ruby 2.7
      @_string ||= to_h.each_with_object([]) { |(name, value), result|
        next if value.nil?

        case value
        when Integer
          result << %W{#{name}#{KEY_VALUE_SEPARATOR}#{value}}
        else
          result << %W{#{name}#{KEY_VALUE_SEPARATOR}"#{value}"}
        end
      }.join(SEPARATOR)
    end

    def to_h
      @_hash ||= {
        KEY_ID => key_id,
        ALGORITHM => Algorithm::HS2019,
        HEADERS => covered_content,
        SIGNATURE => base64_value
      }.tap do |hash|
        hash[CREATED] = created if created
        hash[EXPIRES] = expires if expires
      end
    end

    def covers?(name)
      covered_content.include?(name)
    end

    private

    def assert_valid_values!
      if algorithm != Algorithm::HS2019
        raise UnsupportedAlgorithmError.new(algorithm)
      end

      if covered_content.count == 0
        raise ParameterError, "The covered content list cannot be empty"
      end

      if !created.nil? && !created.is_a?(Integer)
        raise ParameterError, "Invalid 'created' (must be a Unix timestamp integer): '#{created}'"
      end

      if !expires.nil? && !expires.is_a?(Integer)
        raise ParameterError, "Invalid 'expires' (must be a Unix timestamp integer): '#{expires}'"
      end
    end
  end
end