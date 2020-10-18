# frozen_string_literal: true

require "openssl"

module HttpSignatures
  module Algorithm
    class Hmac
      PREFIX = "hmac-"

      def self.make_name(digest_name)
        "#{PREFIX}#{digest_name}"
      end
      SHA1 = make_name(DigestName::SHA1)
      SHA256 = make_name(DigestName::SHA256)

      def initialize(digest_name)
        @digest_name = digest_name
        @digest = OpenSSL::Digest.new(digest_name)
      end

      def name
        "#{PREFIX}#{@digest_name}"
      end

      def sign(key, data)
        OpenSSL::HMAC.digest(@digest, key, data)
      end
    end
  end
end
