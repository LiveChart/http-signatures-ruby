# frozen_string_literal: true

module HttpSignatures
  class Signature
    def initialize(key:, algorithm:, signing_string:)
      @key = key
      @algorithm = algorithm
      @signing_string = signing_string
    end

    def to_str
      @algorithm.sign(@key.secret, @signing_string.to_str)
    end

    def to_base64
      Base64.strict_encode64(to_str)
    end
  end
end
