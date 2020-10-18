# frozen_string_literal: true

module HttpSignatures
  class Verification
    attr_reader :message, :key_store, :max_age

    def initialize(message:, key_store:, max_age: nil)
      @message = message
      @key_store = key_store
      @max_age = max_age
    end

    def valid?
      signature_header_present? && !expired? && VerificationAlgorithm.create(algorithm).valid?(
        key: key,
        provided_signature_base64: provided_signature_base64,
        signing_string: signing_string
      )
    rescue SignatureParameters::ParseError
      false
    end

    private

    def signing_string
      @_signing_string ||= SigningString.new(
        covered_content: covered_content,
        message: message,
        created: parsed_parameters.created,
        expires: parsed_parameters.expires
      )
    end

    def signature_header_present?
      message.header?(Headers::SIGNATURE)
    end

    def provided_signature_base64
      parsed_parameters.signature_base64
    end

    def key
      key_store.fetch(parsed_parameters.key_id)
    end

    def algorithm
      Algorithm.create(parsed_parameters.algorithm)
    end

    def covered_content
      CoveredContent.from_string(parsed_parameters.covered_content)
    end

    def parsed_parameters
      @_parsed_parameters ||= SignatureParameters.parse(message.header(Headers::SIGNATURE))
    end

    def expired?
      now = Time.now.to_i
      expires = parsed_parameters.expires

      return true if expires && expires < now

      return false if max_age.nil?

      created = parsed_parameters.created

      if !created && message.header?(Headers::DATE)
        created = Time.httpdate(message.header(Headers::DATE)).to_i
      end

      return true if created && created + max_age <= now

      false
    end
  end
end
