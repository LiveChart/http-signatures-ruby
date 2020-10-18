# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    def self.create(name)
      case name
      when Hmac::SHA1 then Hmac.new(DigestName::SHA1)
      when Hmac::SHA256 then Hmac.new(DigestName::SHA256)
      when Rsa::SHA1 then Rsa.new(DigestName::SHA1)
      when Rsa::SHA256 then Rsa.new(DigestName::SHA256)
      when Rsa::SHA384 then Rsa.new(DigestName::SHA384)
      when Rsa::SHA512 then Rsa.new(DigestName::SHA512)
      when Hs2019::NAME then Hs2019.new
      else raise UnknownAlgorithm.new(name)
      end
    end

    class UnknownAlgorithm < StandardError
      def initialize(name)
        super("Unknown algorithm name '#{name}'")
      end
    end
  end
end
