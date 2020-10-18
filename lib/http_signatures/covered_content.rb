# frozen_string_literal: true

require "forwardable"

module HttpSignatures
  class CoveredContent
    extend ::Forwardable

    class IllegalHeader < StandardError
      def initialize(names)
        names_string = names.map { |n| "'#{n}'" }.join(", ")
        super("Header #{names_string} not permitted")
      end
    end

    class EmptyCoveredContent < StandardError; end

    REQUEST_TARGET = "(request-target)"

    # Are these useful and will they continue to be in the spec?
    CREATED = "(created)"
    EXPIRES = "(expires)"

    # Cannot sign the signature header
    ILLEGAL = ["signature"]

    def self.from_string(string)
      new(string.split(" "))
    end

    def initialize(names)
      @names = names.map(&:downcase)
      validate_names!
    end

    def to_a
      @names.dup
    end

    def to_str
      @_str ||= @names.join(" ")
    end

    def_delegator :@names, :include?
    def_delegator :@names, :map

    private

    def validate_names!
      raise EmptyCoveredContent if @names.empty?

      raise IllegalHeader, illegal_headers_present if illegal_headers_present.any?
    end

    def illegal_headers_present
      ILLEGAL & @names
    end
  end
end
