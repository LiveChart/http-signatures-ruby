# frozen_string_literal: true

RSpec.describe HttpSignatures::Algorithm::RsaSsaPss do
  include_context "signer/verifier context"

  let(:private_key_material) { OpenSSL::PKey::RSA.new(File.read(File.join(RSPEC_ROOT, "keys", "id_rsa"))) }
  let(:public_key_material) { OpenSSL::PKey::RSA.new(File.read(File.join(RSPEC_ROOT, "keys", "id_rsa.pub"))) }

  include_examples "signer/verifier"
end
