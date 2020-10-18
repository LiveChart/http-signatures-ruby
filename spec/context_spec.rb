# frozen_string_literal: true

require "net/http"

RSpec.describe HttpSignatures::Context do
  let(:http_message) { Net::HTTP::Get.new("/", "date" => "x", "content-length" => "0") }
  let(:message) { HttpSignatures::Message.from(http_message) }

  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub"))) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }

  let(:signing_key_id) { nil }

  subject(:context) do
    HttpSignatures::Context.new(
      signing_key_id: signing_key_id,
      key_store: key_store,
      algorithm: "hs2019",
      headers: %w{(request-target) date content-length},
    )
  end

  let(:key_store) do
    {
      "hello" => {
        public_key: public_key,
        private_key: private_key
      }
    }
  end

  context "with one key in KeyStore, no signing_key_id specified" do
    describe "#signer" do
      it "instantiates Signer with key, algorithm, headers" do
        expect(HttpSignatures::Signer).to receive(:new) do |args|
          expect(args[:key]).to eq(HttpSignatures::Key.new(id: "hello", secret: key_store.values.first))
          expect(args[:algorithm].name).to eq("hs2019")
          expect(args[:covered_content].to_a).to eq(%w{(request-target) date content-length})
        end
        context.signer
      end

      it "signs without errors" do
        expect { context.signer.sign(http_message) }.to_not raise_error
      end

      it "verifies without errors" do
        signature_parameters = 'keyId="hello",algorithm="hs2019",headers="date",signature="x"'
        message = HttpSignatures::Message.from(Net::HTTP::Get.new("/", "Date" => "x", "Signature" => signature_parameters))
        expect { context.verifier.valid?(message) }.to_not raise_error
      end
    end
  end

  context "with two keys in KeyStore, signing_key_id specified" do
    let(:signing_key_id) { "another" }
    let(:key_store) do
      {
        "hello" => {
          public_key: public_key,
          private_key: private_key
        },
        "another" => {
          public_key: public_key,
          private_key: private_key
        }
      }
    end

    describe "#signer" do
      it "instantiates Signer with key, algorithm, headers" do
        expect(HttpSignatures::Signer).to receive(:new) do |args|
          expect(args[:key]).to eq(HttpSignatures::Key.new(id: "another", secret: key_store["another"]))
          expect(args[:algorithm].name).to eq("hs2019")
          expect(args[:covered_content].to_a).to eq(%w{(request-target) date content-length})
        end
        context.signer
      end

      it "signs without errors" do
        context.signer.sign(http_message)
      end
    end
  end
end
