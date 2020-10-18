# frozen_string_literal: true

module HttpSignatures
  class Signer
    def initialize(key:, algorithm:, covered_content:)
      @key = key
      @algorithm = algorithm
      @covered_content = covered_content
    end

    def signature_string(message, created: nil, expires: nil)
      signature_parameters(message, created, expires).to_str
    end

    def sign(request, **kwargs)
      message = Message.from(request)

      headers_target =
        case request
        when Net::HTTPGenericRequest
          request
        when defined?(ActionDispatch) && ActionDispatch::Request
          request.headers
        else
          raise ArgumentError, "Cannot sign #{raw.class}"
        end

      headers_target[Headers::SIGNATURE] = signature_string(message, **kwargs)

      request
    end

    private

    def signature_parameters(message, created, expires)
      SignatureParameters.new(
        key_id: @key.id,
        algorithm: @algorithm.name,
        covered_content: @covered_content.to_str,
        signature_base64: signature(message, created, expires).to_base64,
        created: created,
        expires: expires
      )
    end

    def signature(message, created, expires)
      Signature.new(
        key: @key,
        algorithm: @algorithm,
        signing_string: signing_string(message, created, expires)
      )
    end

    def signing_string(message, created, expires)
      SigningString.new(
        covered_content: @covered_content,
        message: message,
        created: created,
        expires: expires
      )
    end
  end
end
