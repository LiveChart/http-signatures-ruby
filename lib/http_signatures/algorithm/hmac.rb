# frozen_string_literal: true

require "openssl"

module HttpSignatures
  module Algorithm
    class Hmac < Base
      self.name_prefix = "hmac-"

      SHA1 = make_name(DigestName::SHA1)
      SHA256 = make_name(DigestName::SHA256)

      def initialize(digest_name)
        super(digest_name)
        @digest = OpenSSL::Digest.new(digest_name)
      end

      def sign(key, data)
        OpenSSL::HMAC.digest(@digest, key, data)
      end
    end
  end
end
