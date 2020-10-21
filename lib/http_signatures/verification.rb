# frozen_string_literal: true

require "base64"

module HttpSignatures
  class Verification
    class UnknownCreationTimeError < HttpSignatures::Error; end

    attr_reader :key, :signature, :message, :max_age

    def initialize(key:, signature:, message:, max_age: nil)
      @key = key
      @signature = signature
      @message = message
      @max_age = max_age
    end

    def valid?
      valid_signature? && !expired?
    rescue SignatureHeader::ParseError, Message::MissingHeaderError, UnknownCreationTimeError
      false
    end

    private

    def signature_input
      @_signature_input ||= SignatureInput.new(
        message,
        signature.covered_content,
        created: signature.created,
        expires: signature.expires
      )
    end

    def valid_signature?
      decoded_signature = Base64.strict_decode64(signature.base64_value) rescue nil

      return false if decoded_signature.nil?

      signature && key.algorithm.verify(key.secret, decoded_signature, signature_input.to_s)
    end

    def expired?
      expires_at = if signature.expires && signature.covers?(CoveredContent::EXPIRES)
        expires_at = signature.expires
      end

      if max_age
        expires_at ||= if signature.created && signature.covers?(CoveredContent::CREATED)
          signature.created + max_age
        end

        expires_at ||= if message.header?(Header::DATE) && signature.covers?(Header::DATE)
          Time.httpdate(message.header(Header::DATE)).to_i + max_age
        end
      end

      return expires_at <= Time.now.to_i if expires_at

      return false if max_age.nil?

      raise UnknownCreationTimeError
    end
  end
end
