# frozen_string_literal: true

module HttpSignatures
  module Algorithm
    class Base
      class_attribute :name_prefix, instance_writer: false, instance_predicate: false

      attr_reader :digest_name

      def initialize(digest_name)
        @digest_name = digest_name
      end

      def name
        "#{name_prefix}#{digest_name}"
      end

      def ==(other)
        name == other.name
      end

      class << self
        protected

        def make_name(digest_name)
          "#{name_prefix}#{digest_name}"
        end
      end
    end
  end
end
