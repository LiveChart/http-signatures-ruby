# frozen_string_literal: true

module HttpSignatures
  class Verifier
    def valid?(key, signature, message, **kwargs)
      Verification.new(
        key: key,
        signature: signature,
        message: message,
        **kwargs
      ).valid?
    end
  end
end
