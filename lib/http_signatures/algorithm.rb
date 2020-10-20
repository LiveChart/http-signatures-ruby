# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class UnknownAlgorithm < HttpSignatures::Error
      def initialize(name)
        super("Unknown algorithm name '#{name}'")
      end
    end

    def self.create(name)
      case name
        when Hs2019::NAME then Hs2019.new
        else raise UnknownAlgorithm.new(name)
      end
    end
  end
end
