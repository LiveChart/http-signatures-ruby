# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    module Asymmetric
      def sign(key, data)
        OpenSSL::PKey::RSA.new(private_key(key)).sign(digest_name, data)
      end

      def verify(key, sign, data)
        OpenSSL::PKey::RSA.new(public_key(key)).verify(digest_name, sign, data)
      end

      private

      def private_key(key)
        key.fetch(:private_key)
      end

      def public_key(key)
        key.fetch(:public_key)
      end
    end
  end
end
