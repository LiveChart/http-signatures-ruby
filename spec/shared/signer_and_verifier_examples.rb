# frozen_string_literal: true

RSpec.shared_examples "signer/verifier" do
  describe "signer.sign and verifier.valid?" do
    context "headers are %w{date}" do
      let(:headers) { %w{date} }
      it_behaves_like "signer"
      it_behaves_like "verifier"
    end

    context "headers are %w{(request-target) host date}" do
      let(:headers) { %w{(request-target) host date} }
      it_behaves_like "signer"
      it_behaves_like "verifier"
    end
  end
end
