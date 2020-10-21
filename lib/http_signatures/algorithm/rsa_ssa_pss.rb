# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class RsaSsaPss < Base
      self.name = "RSASSA-PSS"
      self.digest_name = DigestName::SHA512

      def sign(private_key, data)
        OpenSSL::PKey::RSA.new(private_key).sign_pss(
          digest_name,
          data,
          salt_length: :max,
          mgf1_hash: digest_name
        )
      end

      def verify(public_key, signed_data, data)
        OpenSSL::PKey::RSA.new(public_key).verify_pss(
          digest_name,
          signed_data,
          data,
          salt_length: :auto,
          mgf1_hash: digest_name
        )
      end
    end
  end
end
