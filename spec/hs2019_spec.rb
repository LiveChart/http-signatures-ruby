# frozen_string_literal: true

# NOTE: All test data in this spec are same as
# https://github.com/tomitribe/http-signatures-java/blob/master/src/test/java/org/tomitribe/auth/signatures/RsaTest.java

require "net/http"

RSpec.shared_examples_for "signer" do
  it "returns expected signature" do
    context.signer.sign(http_message)
    expect(context.verifier.valid?(HttpSignatures::Message.from(http_message))).to eq(true)
  end
end

RSpec.shared_examples_for "verifier" do
  it "validates signature" do
    context.signer.sign(http_message)
    expect(context.verifier.valid?(HttpSignatures::Message.from(http_message))).to eq(true)
  end

  it "rejects if a signed header has changed" do
    context.signer.sign(http_message)
    http_message["Date"] = "Thu, 12 Jan 2012 21:31:40 GMT"
    expect(context.verifier.valid?(HttpSignatures::Message.from(http_message))).to eq(false)
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

  let(:algorithm) { "hs2019" }

  let(:context) do
    HttpSignatures::Context.new(
      key_store: {
        "my_rsa_key_pair" => {
          private_key: private_key,
          public_key: public_key,
        },
      },
      signing_key_id: "my_rsa_key_pair",
      algorithm: algorithm,
      headers: headers,
    )
  end

  describe "context.signer.sign and context.verifier.valid?" do
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
