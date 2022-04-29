# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class Ed25519 < Base
      self.name = "Ed25519"
      self.digest_name = nil

      def sign(private_key, data)
        private_key = OpenSSL::PKey.read(private_key) if private_key.is_a?(String)
        oid = private_key.oid

        raise KeyError, "Received '#{oid}' key instead of ED25519" unless oid == "ED25519"

        private_key.sign(digest_name, data)
      end

      def verify(public_key, signed_data, data)
        public_key = OpenSSL::PKey.read(public_key) if public_key.is_a?(String)
        oid = public_key.oid

        raise KeyError, "Received '#{oid}' key instead of ED25519" unless oid == "ED25519"

        public_key.verify(digest_name, signed_data, data)
      end
    end
  end
end
