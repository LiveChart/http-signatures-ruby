# frozen_string_literal: true

require "net/http"

RSpec.describe HttpSignatures::Signer do

  EXAMPLE_DATE = "Mon, 28 Jul 2014 15:39:13 -0700"

  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub"))) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }

  subject(:signer) do
    HttpSignatures::Signer.new(key: key, algorithm: algorithm, covered_content: covered_content)
  end
  let(:key) { HttpSignatures::Key.new(id: "pda", secret: { public_key: public_key, private_key: private_key } ) }
  let(:algorithm) { HttpSignatures::Algorithm::Hs2019.new }
  let(:covered_content) { HttpSignatures::CoveredContent.new(["date", "content-type"]) }

  let(:http_message) do
    Net::HTTP::Get.new(
      "/path?query=123",
      "Date" => EXAMPLE_DATE,
      "Content-Type" => "text/plain",
      "Content-Length" => "123",
    )
  end

  let(:message) { HttpSignatures::Message.from(http_message) }

  let(:signature_structure_pattern) do
    %r{
      \A
      keyId="[\w-]+",
      algorithm="[\w-]+",
      (?:headers=".*",)?
      signature="[a-zA-Z0-9/+=]+"
      \z
    }x
  end

  describe "#signature_string" do
    it "passes correct signing string to algorithm" do
      expect(algorithm).to receive(:sign).with(
        key.secret,
        ["date: #{EXAMPLE_DATE}", "content-type: text/plain"].join("\n")
      ).at_least(:once).and_return("static")
      signer.signature_string(message)
    end

    it "returns a string" do
      expect(signer.signature_string(message)).to be_a(String)
    end
  end

  describe "#sign" do
    it "passes correct signing string to algorithm" do
      expect(algorithm).to receive(:sign).with(
        key.secret,
        ["date: #{EXAMPLE_DATE}", "content-type: text/plain"].join("\n")
      ).at_least(:once).and_return("static")
      signer.sign(http_message)
    end

    it "returns reference to the mutated input" do
      expect(signer.sign(http_message)).to eq(http_message)
    end
  end

  context "after signing" do
    before do
      allow_any_instance_of(HttpSignatures::SignatureParameters).to receive(:signature_base64).and_return("b64sig")
      signer.sign(http_message)
    end

    it "has valid Signature header structure" do
      expect(http_message["Signature"]).to match(signature_structure_pattern)
    end

    it "matches expected Signature header" do
      expect(http_message["Signature"]).to eq <<~TEXT.chomp
        keyId="pda",algorithm="hs2019",headers="date content-type",signature="b64sig"
      TEXT
    end
  end
end
