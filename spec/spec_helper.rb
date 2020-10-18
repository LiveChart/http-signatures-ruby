# frozen_string_literal: true

require "http_signatures"
require "timecop"

# http://rubydoc.info/gems/rspec-core/RSpec/Core/Configuration
RSpec.configure do |c|

  c.color = true

  c.default_formatter = "documentation"

  c.disable_monkey_patching!

end
