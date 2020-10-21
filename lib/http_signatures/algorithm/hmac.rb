# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class HMAC < Base
      self.name = "HMAC"
      self.digest_name = DigestName::SHA512

      def sign(private_key, data)
        OpenSSL::HMAC.digest(digest_name, private_key, data)
      end

      def verify(private_key, signed_data, data)
        signed_data == sign(private_key, data)
      end
    end
  end
end
