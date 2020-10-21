# frozen_string_literal: true

# NOTE: All test data in this spec are same as
# https://github.com/tomitribe/http-signatures-java/blob/master/src/test/java/org/tomitribe/auth/signatures/RsaTest.java

require "net/http"

RSpec.shared_context "signer/verifier context" do
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

  let(:algorithm) { described_class.new }

  let(:headers) { }

  let(:covered_content) { HttpSignatures::CoveredContent.new(headers) }

  let(:private_key_material) { } # OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa")))
  let(:private_key) { HttpSignatures::Key.new(id: "pda", secret: private_key_material, algorithm: algorithm) }
  let(:signer) { HttpSignatures::Signer.new(private_key, covered_content) }

  let(:public_key_material) { } # OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub")))
  let(:public_key) { HttpSignatures::Key.new(id: "pda", secret: public_key_material, algorithm: algorithm) }
  let(:verifier) { HttpSignatures::Verifier.new }
end
