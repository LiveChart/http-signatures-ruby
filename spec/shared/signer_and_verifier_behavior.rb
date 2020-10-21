# frozen_string_literal: true

# NOTE: All test data in this spec are same as
# https://github.com/tomitribe/http-signatures-java/blob/master/src/test/java/org/tomitribe/auth/signatures/RsaTest.java

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
