# frozen_string_literal: true

require "http_signatures"
require "timecop"

RSPEC_ROOT = File.dirname(__FILE__)

Dir[File.dirname(__FILE__) + "/shared/*.rb"].each { |f| require f }

# http://rubydoc.info/gems/rspec-core/RSpec/Core/Configuration
RSpec.configure do |c|

  c.color = true

  c.default_formatter = "documentation"

  c.disable_monkey_patching!

end
