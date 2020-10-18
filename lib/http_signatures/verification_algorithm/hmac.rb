# frozen_string_literal: true

module HttpSignatures
  module VerificationAlgorithm
    class Hmac < Base
      self.algorithm_class = Algorithm::Hmac

      def valid?(
        key:,
        provided_signature_base64:,
        signing_string:
      )
        Signature.new(
          key: key,
          algorithm: @algorithm,
          signing_string: signing_string
        ).to_base64 == provided_signature_base64
      end
    end
  end
end