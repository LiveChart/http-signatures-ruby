module HttpSignatures
  class SignatureParameters
    class ParseError < StandardError; end
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

          if !SignatureParameters::ALL_PARAMETERS.include?(name)
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
          signature_base64: parts[SIGNATURE],
          created: parts[CREATED],
          expires: parts[EXPIRES]
        )
      end
    end

    attr_reader :key_id, :algorithm, :covered_content, :signature_base64, :expires, :created

    def initialize(key_id:, algorithm:, covered_content:, signature_base64:, created: nil, expires: nil)
      @key_id = key_id
      @algorithm = algorithm
      @covered_content = covered_content
      @signature_base64 = signature_base64
      @created = created
      @expires = expires
    end

    def to_str
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
        ALGORITHM => algorithm,
        HEADERS => covered_content,
        SIGNATURE => signature_base64
      }.tap do |hash|
        hash[CREATED] = created if created
        hash[EXPIRES] = expires if expires
      end
    end
  end
end