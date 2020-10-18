# frozen_string_literal: true

require "base64"

module HttpSignatures
  module VerificationAlgorithm
    class Rsa < Base
      self.algorithm_class = Algorithm::Rsa

      def valid?(
        key:,
        provided_signature_base64:,
        signing_string:
      )
        @algorithm.verify(
          key.secret,
          Base64.strict_decode64(provided_signature_base64),
          signing_string.to_str
        )
      end
    end
  end
end
