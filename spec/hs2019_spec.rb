# frozen_string_literal: true

# NOTE: All test data in this spec are same as
# https://github.com/tomitribe/http-signatures-java/blob/master/src/test/java/org/tomitribe/auth/signatures/RsaTest.java

require "net/http"

RSpec.shared_examples_for "signer" do
  it "returns expected signature" do
    signer.sign(http_message)
    signature = HttpSignatures::SignatureHeader.parse(http_message["Signature"])
    expect(verifier.valid?(public_key, signature, HttpSignatures::Message.from(http_message))).to eq(true)
  end
end

RSpec.shared_examples_for "verifier" do
  it "validates signature" do
    signer.sign(http_message)
    signature = HttpSignatures::SignatureHeader.parse(http_message["Signature"])
    expect(verifier.valid?(public_key, signature, HttpSignatures::Message.from(http_message))).to eq(true)
  end

  it "rejects if a signed header has changed" do
    signer.sign(http_message)
    http_message["Date"] = "Thu, 12 Jan 2012 21:31:40 GMT"
    signature = HttpSignatures::SignatureHeader.parse(http_message["Signature"])
    expect(verifier.valid?(public_key, signature, HttpSignatures::Message.from(http_message))).to eq(false)
  end
end

RSpec.describe "Using RSA" do
  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub"))) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }

  let(:http_message) do
    Net::HTTP::Post.new(
      "/foo?param=value&pet=dog",
      "Host" => "example.org",
      "Date" => "Thu, 05 Jan 2012 21:31:40 GMT",
      "Content-Type" => "application/json",
      "Digest" => "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
      "Accept" => "*/*",
      "Content-Length" => "18"
    )
  end

  let(:message) { HttpSignatures::Message.from(http_message) }

  let(:algorithm) { HttpSignatures::Algorithm::Hs2019.new }

  let(:headers) { }

  let(:covered_content) { HttpSignatures::CoveredContent.new(headers) }

  let(:private_key_value) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }
  let(:private_key) { HttpSignatures::Key.new(id: "pda", secret: private_key_value) }
  let(:signer) { HttpSignatures::Signer.new(private_key, algorithm, covered_content) }

  let(:public_key_value) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub"))) }
  let(:public_key) { HttpSignatures::Key.new(id: "pda", secret: public_key_value) }
  let(:verifier) { HttpSignatures::Verifier.new }

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
