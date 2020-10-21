# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class ECDSA < Base
      self.name = "ECDSA"
      self.digest_name = DigestName::SHA512

      def sign(private_key, data)
        OpenSSL::PKey::EC.new(private_key).sign(digest_name, data)
      end

      def verify(public_key, sign, data)
        OpenSSL::PKey::EC.new(public_key).verify(digest_name, sign, data)
      end
    end
  end
end
