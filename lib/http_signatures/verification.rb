# frozen_string_literal: true

require "base64"

module HttpSignatures
  class Verification
    attr_reader :key, :signature, :message, :max_age

    def initialize(key:, signature:, message:, max_age: nil)
      @key = key
      @signature = signature
      @message = message
      @max_age = max_age
    end

    def valid?
      decoded_signature = Base64.strict_decode64(signature.base64_value) rescue nil

      return false if decoded_signature.nil?

      signature && !expired? && key.algorithm.verify(
        key.secret,
        decoded_signature,
        signature_input.to_s
      )
    rescue SignatureHeader::ParseError, Message::MissingHeaderError
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

    def expired?
      now = Time.now.to_i
      expires = signature.expires

      return true if expires && expires < now

      return false if max_age.nil?

      created = signature.created

      if !created && message.header?(Header::DATE) && signature.covered_content.include?(Header::DATE)
        created = Time.httpdate(message.header(Header::DATE)).to_i
      end

      return true if created && created + max_age <= now

      false
    end
  end
end
