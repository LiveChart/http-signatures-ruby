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

    it "defaults 'algorithm' to 'hs2019' when a value is not specified" do
      sig = HttpSignatures::SignatureHeader.new(
        key_id: key_id,
        covered_content: covered_content,
        base64_value: base64_value,
        created: created,
        expires: expires
      )
      expect(sig.algorithm).to eq("hs2019")
    end

    it "defaults 'covered_content' to '(created)' when a value is not specified" do
      sig = HttpSignatures::SignatureHeader.new(
        key_id: key_id,
        algorithm: algorithm_name,
        base64_value: base64_value,
        created: created,
        expires: expires
      )
      expect(sig.covered_content.to_a).to eq(["(created)"])
    end

    it "defaults 'created' to nil when a value is not specified" do
      sig = HttpSignatures::SignatureHeader.new(
        key_id: key_id,
        algorithm: algorithm_name,
        base64_value: base64_value,
      )
      expect(sig.created).to eq(nil)
    end

    it "defaults 'expires' to nil when a value is not specified" do
      sig = HttpSignatures::SignatureHeader.new(
        key_id: key_id,
        algorithm: algorithm_name,
        base64_value: base64_value,
      )
      expect(sig.expires).to eq(nil)
    end

    context "provided algorithm=rsa-sha256" do
      let(:algorithm_name) { "rsa-sha256" }

      it "raises an explanatory error" do
        expect { signature_header }.to raise_error(HttpSignatures::SignatureHeader::UnsupportedAlgorithmError, "Unsupported algorithm: rsa-sha256")
      end
    end

    context "provided covered_content=''" do
      let(:covered_content) { "" }

      it "raises an error" do
        expect { signature_header }.to raise_error(HttpSignatures::CoveredContent::EmptyCoveredContent)
      end
    end

    [
      "",
      0.0,
      "2020-10-21 08:41:05 UTC",
      "1603269678"
    ].each do |invalid_timestamp|
      context "provided created=#{invalid_timestamp} (#{invalid_timestamp.class})" do
        let(:created) { invalid_timestamp }

        it "raises an explanatory error" do
          expect { signature_header }.
            to raise_error(
              HttpSignatures::SignatureHeader::ParameterError,
              "Invalid 'created' (must be a Unix timestamp integer): '#{invalid_timestamp}'"
            )
        end
      end

      context "provided expires=#{invalid_timestamp} (#{invalid_timestamp.class})" do
        let(:expires) { invalid_timestamp }

        it "raises an explanatory error" do
          expect { signature_header }.
            to raise_error(
              HttpSignatures::SignatureHeader::ParameterError,
              "Invalid 'expires' (must be a Unix timestamp integer): '#{invalid_timestamp}'"
            )
        end
      end
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

    context "provided an algorithm other than hs2019" do
      let(:input) do
        'keyId="example",algorithm="rsa-sha256",headers="(request-target) date",signature="b64"'
      end

      it "raises an explanatory error" do
        expect { parsed }.to raise_error(HttpSignatures::SignatureHeader::UnsupportedAlgorithmError, "Unsupported algorithm: rsa-sha256")
      end
    end

    context "provided input without a specified algorithm" do
      let(:input) do
        'keyId="example",headers="(request-target) date",signature="b64"'
      end

      it "defaults to hs2019" do
        expect(parsed.algorithm).to eq("hs2019")
      end
    end

    context "provided input without headers specified" do
      let(:input) do
        'keyId="example",signature="b64"'
      end

      it "defaults to '(created)'" do
        expect(parsed.covered_content.to_a).to eq(%w[(created)])
      end
    end

    context "provided input without a signature" do
      let(:input) do
        'keyId="example",algorithm="hs2019",headers="(request-target) date"'
      end

      it "raises an explanatory error" do
        expect { parsed }.to raise_error(HttpSignatures::SignatureHeader::ParseError, "Missing required parameter: signature")
      end
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

    [
      0.1,
      '"10"',
      '0 0',
    ].each do |invalid_value|
      %i[created expires].each do |parameter_name|
        context "with #{parameter_name}=#{invalid_value}" do
          let(:input) do
            %Q{algorithm="hs2019",headers="(request-target) date",signature="b64",#{parameter_name}=#{invalid_value}}
          end

          it "fails with explanatory error message" do
            expect { parsed }.
              to raise_error(HttpSignatures::SignatureHeader::ParseError, "Invalid value for #{parameter_name} (must be an integer): #{invalid_value}")
          end
        end
      end
    end
  end

  describe "#covers?" do
    let(:covered_content) { "date" }

    it "correctly validates a covered value" do
      expect(signature_header.covers?("dAtE")).to eq(true)
    end

    it "correctly checks presence" do
      expect(signature_header.covers?("digest")).to eq(false)
    end
  end
end
