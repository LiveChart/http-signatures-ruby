# frozen_string_literal: true

module HttpSignatures
  module VerificationAlgorithm
    class Base
      class_attribute :algorithm_class, instance_writer: false, instance_predicate: false

      def initialize(algorithm)
        raise ArgumentError, "Invalid algorithm: #{algorithm}" unless algorithm.is_a?(self.class.algorithm_class)
        @algorithm = algorithm
      end

      def valid?(
        key:,
        provided_signature_base64:,
        signing_string:
      )
        raise NotImplementedError
      end
    end
  end
end
