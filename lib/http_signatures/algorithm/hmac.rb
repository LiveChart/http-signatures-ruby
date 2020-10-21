# frozen_string_literal: true

require "active_support/security_utils"

module HttpSignatures
  module Algorithm
    class HMAC < Base
      self.name = "HMAC"
      self.digest_name = DigestName::SHA512

      def sign(private_key, data)
        OpenSSL::HMAC.digest(digest_name, private_key, data)
      end

      def verify(private_key, signed_data, data)
        ActiveSupport::SecurityUtils.fixed_length_secure_compare(
          signed_data,
          sign(private_key, data)
        )
      end
    end
  end
end
