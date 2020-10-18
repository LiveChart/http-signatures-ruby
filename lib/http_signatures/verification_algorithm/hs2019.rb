# frozen_string_literal: true

require "base64"

module HttpSignatures
  module VerificationAlgorithm
    class Hs2019 < Base
      self.algorithm_class = Algorithm::Hs2019

      def valid?(
        key:,
        provided_signature_base64:,
        signing_string:
      )
        decoded_signature = Base64.strict_decode64(provided_signature_base64) rescue nil

        return false if decoded_signature.nil?

        @algorithm.verify(key.secret, decoded_signature, signing_string.to_str)
      end
    end
  end
end
