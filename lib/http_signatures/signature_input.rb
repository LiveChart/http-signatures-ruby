# frozen_string_literal: true

module HttpSignatures
  class SignatureInput
    attr_reader :covered_content, :message, :created, :expires

    def initialize(message, covered_content, created: nil, expires: nil)
      @message = message
      @covered_content = covered_content
      @created = created
      @expires = expires
    end

    def to_s
      covered_content.map { |name| "%s: %s" % [name, covered_content_value(name)] }.join("\n")
    end

    private

    def covered_content_value(name)
      case name
      when CoveredContent::REQUEST_TARGET
        message.request_target
      when CoveredContent::CREATED
        created
      when CoveredContent::EXPIRES
        expires
      else
        message.header!(name)
      end
    end
  end
end
