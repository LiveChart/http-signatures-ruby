# frozen_string_literal: true

RSpec.describe HttpSignatures::SignatureHeader do
  subject(:signature_header) do
    HttpSignatures::SignatureHeader.new(
      key_id: key_id,
      algorithm: algorithm_name,
      covered_content: covered_content,
      base64_value: base64_value,
      created: created,
      expires: expires
    )
  end

  let(:key_id) { "pda" }
  let(:algorithm_name) { "hs2019" }
  let(:covered_content) { "a b c" }
  let(:base64_value) { "c2lnc3RyaW5n" }
  let(:created) { 1602993083 }
  let(:expires) { 1602993083 }

  describe ".new" do
    it "does not raise provided valid values" do
      expect { signature_header }.not_to raise_error
    end
  end

  describe "#to_s" do
    it "builds parameters into string" do
      expect(signature_header.to_s).to eq(
        'keyId="pda",algorithm="hs2019",headers="a b c",signature="c2lnc3RyaW5n",created=1602993083,expires=1602993083'
      )
    end
  end

  describe ".parse" do
    subject(:parsed) { HttpSignatures::SignatureHeader.parse(input) }

    let(:input) do
      'keyId="example",algorithm="hs2019",headers="(request-target) date",signature="b64",created=1602993083,expires=1602993084'
    end

    it "returns a HttpSignatures::SignatureHeader" do
      expect(parsed).to be_a(HttpSignatures::SignatureHeader)
    end

    it "returns the correct values" do
      expect(parsed.algorithm).to eq("hs2019")
      expect(parsed.covered_content.to_a).to eq(["(request-target)", "date"])
      expect(parsed).to have_attributes(
        {
          key_id: "example",
          base64_value: "b64",
          created: 1602993083,
          expires: 1602993084
        }
      )
    end

    context "with invalid input" do
      let(:input) do
        'foo="bar",algorithm="hs2019",headers="(request-target) date",signature="b64"'
      end

      it "fails with explanatory error message" do
        expect { parsed }.
          to raise_error(HttpSignatures::SignatureHeader::ParseError, 'Unparseable segment: foo="bar"')
      end
    end
  end
end
