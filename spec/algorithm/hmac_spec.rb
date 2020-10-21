# frozen_string_literal: true

RSpec.describe HttpSignatures::Algorithm::HMAC do
  include_context "signer/verifier context"

  let(:private_key_material) { "testkey" }
  let(:public_key_material) { "testkey" }

  include_examples "signer/verifier"
end
