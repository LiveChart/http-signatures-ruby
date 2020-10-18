module HttpSignatures
  class SigningString
    attr_reader :covered_content, :message, :created, :expires

    def initialize(covered_content:, message:, created: nil, expires: nil)
      @covered_content = covered_content
      @message = message
      @created = created
      @expires = expires
    end

    def to_str
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
