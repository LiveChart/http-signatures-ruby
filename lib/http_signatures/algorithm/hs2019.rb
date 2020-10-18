# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class Hs2019
      NAME = "hs2019"

      DIGEST = DigestName::SHA512

      def name
        NAME
      end

      def sign(key, data, salt_length: :max, hash: DIGEST)
        key = key[:private_key]

        raise ArgumentError, "Invalid key type: #{key.class}" unless key.is_a?(OpenSSL::PKey::RSA)
        raise ArgumentError, "Can't sign without the private key" unless key.private?

        key.sign_pss(DIGEST, data, salt_length: salt_length, mgf1_hash: hash)
      end

      def verify(key, signed_data, data, salt_length: :auto, hash: DIGEST)
        key = key[:public_key]

        raise ArgumentError, "Invalid key type: #{key.class}" unless key.is_a?(OpenSSL::PKey::RSA)
        raise ArgumentError, "Can't verify without the public key" unless key.public?

        key.verify_pss(DIGEST, signed_data, data, salt_length: salt_length, mgf1_hash: hash)
      end
    end
  end
end
