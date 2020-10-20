# frozen_string_literal: true

require "net/http"

RSpec.describe HttpSignatures::Signer do
  EXAMPLE_DATE = "Mon, 28 Jul 2014 15:39:13 -0700"

  let(:private_key_value) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }

  let(:private_key) { HttpSignatures::Key.new(id: "pda", secret: private_key_value) }

  let(:key) { private_key }

  subject(:signer) do
    described_class.new(key, algorithm, covered_content)
  end
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

  describe "#signature_header" do
    it "passes correct signing string to algorithm" do
      expect(algorithm).to receive(:sign).with(
        key.secret,
        ["date: #{EXAMPLE_DATE}", "content-type: text/plain"].join("\n")
      ).at_least(:once).and_return("static")
      signer.signature_header(message)
    end

    it "returns a string" do
      expect(signer.signature_header(message)).to be_a(HttpSignatures::SignatureHeader)
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
      allow_any_instance_of(HttpSignatures::SignatureHeader).to receive(:base64_value).and_return("b64sig")
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
