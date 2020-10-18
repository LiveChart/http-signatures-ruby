# frozen_string_literal: true

RSpec.describe HttpSignatures::SignatureParameters do
  subject(:signature_parameters) do
    HttpSignatures::SignatureParameters.new(
      key_id: key_id,
      algorithm: algorithm_name,
      covered_content: covered_content,
      signature_base64: signature_base64,
      created: created
    )
  end

  let(:key_id) { "pda" }
  let(:algorithm_name) { "hmac-test" }
  let(:covered_content) { "a b c" }
  let(:signature_base64) { "c2lnc3RyaW5n" }
  let(:created) { 1602993083 }

  describe "#to_str" do
    it "builds parameters into string" do
      expect(signature_parameters.to_str).to eq(
        'keyId="pda",algorithm="hmac-test",headers="a b c",signature="c2lnc3RyaW5n",created=1602993083'
      )
    end
  end

  describe ".parse" do
    subject(:parsed) { HttpSignatures::SignatureParameters.parse(input) }

    let(:input) do
      'keyId="example",algorithm="hmac-sha1",headers="(request-target) date",signature="b64",created=1602993083,expires=1602993084'
    end

    it "returns a HttpSignatures::SignatureParameters" do
      expect(parsed).to be_a(HttpSignatures::SignatureParameters)
    end

    it "returns the correct values" do
      expect(parsed).to have_attributes(
        {
          key_id: "example",
          algorithm: "hmac-sha1",
          covered_content: "(request-target) date",
          signature_base64: "b64",
          created: 1602993083,
          expires: 1602993084
        }
      )
    end

    context "with invalid input" do
      let(:input) do
        'foo="bar",algorithm="hmac-sha1",headers="(request-target) date",signature="b64"'
      end

      it "fails with explanatory error message" do
        expect { parsed }.
          to raise_error(HttpSignatures::SignatureParameters::ParseError, 'Unparseable segment: foo="bar"')
      end
    end
  end
end
