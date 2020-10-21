# frozen_string_literal: true

RSpec.describe HttpSignatures::Algorithm::ECDSA do
  include_context "signer/verifier context"

  let(:private_key_material) { OpenSSL::PKey::EC.new(File.read(File.join(RSPEC_ROOT, "keys", "id_ec"))) }
  let(:public_key_material) { OpenSSL::PKey::EC.new(File.read(File.join(RSPEC_ROOT, "keys", "id_ec.pub"))) }

  include_examples "signer/verifier"
end
