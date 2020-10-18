# frozen_string_literal: true

require "net/http"

RSpec.describe HttpSignatures::SigningString do
  DATE = "Tue, 29 Jul 2014 14:17:02 -0700"

  subject(:signing_string) do
    HttpSignatures::SigningString.new(
      covered_content: covered_content,
      message: message,
      created: created,
      expires: expires
    )
  end

  let(:covered_content_string) { "(request-target) date" }
  let(:created) { nil }
  let(:expires) { nil }

  let(:covered_content) { HttpSignatures::CoveredContent.from_string(covered_content_string) }

  let(:message) do
    HttpSignatures::Message.from(
      Net::HTTP::Get.new("/path?query=123", "date" => DATE, "x-herring" => "red")
    )
  end

  describe "#to_str" do
    it "returns correct signing string" do
      expect(signing_string.to_str).to eq <<~TEXT.chomp
        (request-target): get /path?query=123
        date: #{DATE}
      TEXT
    end

    context "for header not in message" do
      let(:covered_content) { HttpSignatures::CoveredContent.from_string("nope") }
      it "raises MissingHeaderError" do
        expect {
          signing_string.to_str
        }.to raise_error(HttpSignatures::Message::MissingHeaderError)
      end
    end

    context "with an expiration time" do
      let(:expires) { 1414849972 }
      let(:covered_content_string) { "(request-target) (expires)" }

      it "returns correct signing string" do
        expect(signing_string.to_str).to eq <<~TEXT.chomp
          (request-target): get /path?query=123
          (expires): 1414849972
        TEXT
      end
    end

    context "with a creation time" do
      let(:created) { 1414849972 }
      let(:covered_content_string) { "(request-target) (created)" }

      it "returns correct signing string" do
        expect(signing_string.to_str).to eq <<~TEXT.chomp
          (request-target): get /path?query=123
          (created): 1414849972
        TEXT
      end
    end
  end
end
