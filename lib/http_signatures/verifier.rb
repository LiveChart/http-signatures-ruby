module HttpSignatures
  class Verifier
    def initialize(key_store:)
      @key_store = key_store
    end

    def valid?(message, **opts)
      Verification.new(
        message: message,
        key_store: @key_store,
        **opts
      ).valid?
    end
  end
end
