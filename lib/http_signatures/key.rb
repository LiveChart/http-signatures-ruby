module HttpSignatures
  class Key
    attr_reader :id, :secret

    def initialize(id:, secret:)
      @id = id
      @secret = secret
    end

    def ==(other)
      self.class == other.class &&
        self.id == other.id &&
        self.secret == other.secret
    end
  end
end
