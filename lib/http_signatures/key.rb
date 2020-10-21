# frozen_string_literal: true

module HttpSignatures
  class Key
    attr_reader :id, :secret, :algorithm

    def initialize(id:, secret:, algorithm:)
      @id = id
      @secret = secret
      @algorithm = algorithm
    end

    def ==(other)
      self.class == other.class &&
        self.id == other.id &&
        self.secret == other.secret &&
        self.algorithm == other.algorithm
    end
  end
end
