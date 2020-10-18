require "openssl"

module HttpSignatures
  module Algorithm
    class Rsa
      PREFIX = "rsa-"

      def self.make_name(digest_name)
        "#{PREFIX}#{digest_name}"
      end

      SHA1 = make_name(DigestName::SHA1)
      SHA256 = make_name(DigestName::SHA256)
      SHA384 = make_name(DigestName::SHA384)
      SHA512 = make_name(DigestName::SHA512)

      def initialize(digest_name)
        @digest_name = digest_name
      end

      def name
        "#{PREFIX}#{@digest_name}"
      end

      def sign(key, data)
        OpenSSL::PKey::RSA.new(private_key(key)).sign(@digest_name, data)
      end

      def verify(key, sign, data)
        OpenSSL::PKey::RSA.new(public_key(key)).verify(@digest_name, sign, data)
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
