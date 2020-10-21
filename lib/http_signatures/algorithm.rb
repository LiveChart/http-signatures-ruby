# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class UnknownAlgorithm < HttpSignatures::Error
      def initialize(name)
        super("Unknown algorithm name '#{name}'")
      end
    end

    HS2019 = "hs2019"
  end
end
