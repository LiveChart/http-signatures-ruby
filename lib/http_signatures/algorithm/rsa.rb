# frozen_string_literal: true

require "openssl"

module HttpSignatures
  module Algorithm
    class Rsa < Base
      include Asymmetric

      self.name_prefix = "rsa-"

      SHA1 = make_name(DigestName::SHA1)
      SHA256 = make_name(DigestName::SHA256)
      SHA384 = make_name(DigestName::SHA384)
      SHA512 = make_name(DigestName::SHA512)
    end
  end
end
