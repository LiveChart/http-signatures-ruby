# frozen_string_literal: true

RSpec.describe HttpSignatures::Algorithm::Ed25519 do
  include_context "signer/verifier context"

  let(:private_key_material) { OpenSSL::PKey.read(File.read(File.join(RSPEC_ROOT, "keys", "id_ed25519"))) }
  let(:public_key_material) { OpenSSL::PKey.read(File.read(File.join(RSPEC_ROOT, "keys", "id_ed25519.pub"))) }

  include_examples "signer/verifier"
end
