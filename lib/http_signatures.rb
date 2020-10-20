# frozen_string_literal: true

require "active_support"
require "active_support/core_ext/class/attribute"

require "http_signatures/error"
require "http_signatures/header"
require "http_signatures/algorithm"
require "http_signatures/algorithm/base"
require "http_signatures/algorithm/digest_name"
require "http_signatures/algorithm/hs2019"
require "http_signatures/covered_content"
require "http_signatures/key"
require "http_signatures/signature_input"
require "http_signatures/signature_header"
require "http_signatures/signer"
require "http_signatures/verification"
require "http_signatures/verifier"
require "http_signatures/message"
require "http_signatures/version"

module HttpSignatures
end
