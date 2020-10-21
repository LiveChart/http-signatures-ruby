# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class Base
      class_attribute :name, instance_writer: false, instance_predicate: false
      class_attribute :digest_name, instance_writer: false, instance_predicate: false

      def ==(other)
        name == other.name
      end
    end
  end
end
