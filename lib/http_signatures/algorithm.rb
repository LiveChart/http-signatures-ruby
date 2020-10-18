# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    def self.create(name)
      case name
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
