# frozen_string_literal: true

require "net/http"
require "time"

RSpec.describe HttpSignatures::Verifier do

  DATE = "Fri, 01 Nov 2014 13:44:32 GMT"
  DATE_DIFFERENT = "Fri, 01 Nov 2014 13:44:33 GMT"

  let(:date) { Time.httpdate(DATE) }

  let(:created) { nil }
  let(:expires) { nil }

  subject(:verifier) { HttpSignatures::Verifier.new(key_store: key_store) }
  let(:key_store) { HttpSignatures::KeyStore.new("pda" => "secret") }
  let(:http_message) { Net::HTTP::Get.new("/path?query=123", headers) }
  let(:message) { HttpSignatures::Message.from(http_message) }
  let(:headers) { { "Date" => DATE, "Signature" => signature_header } }

  let(:signature_header) do
    'keyId="%s",algorithm="%s",headers="%s",signature="%s"' % [
      "pda",
      "hmac-sha256",
      "(request-target) date",
      "Co4yhhwmZM+GILYIjxaEsecm6UadTfahtxohaguAnbg=",
    ]
  end

  it "verifies a valid message" do
    expect(verifier.valid?(message)).to eq(true)
  end

  it "rejects message with missing headers" do
    headers.clear
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered path" do
    message.path << "x"
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered date" do
    message["Date"] = DATE_DIFFERENT
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with tampered signature" do
    message["Signature"] = message["Signature"].sub('signature="', 'signature="x')
    expect(verifier.valid?(message)).to eq(false)
  end

  it "rejects message with malformed signature" do
    message["Signature"] = "foo=bar,baz=bla,yadda=yadda"
    expect(verifier.valid?(message)).to eq(false)
  end

  context "with an expiration" do
    let(:created) { 1414849472 }
    let(:expires) { 1414849972 }
    let(:expires_at) { Time.at(expires) }

    let(:signature_header) do
      'keyId="%s",algorithm="%s",headers="%s",signature="%s",expires=%s' % [
        "pda",
        "hmac-sha256",
        "(request-target) (expires)",
        "5NJ0tf0nLKIButgu5ghdpyZqRBiOhjQIlb+wxXeH7D4=",
        expires
      ]
    end

    it "verifies an unexpired message" do
      Timecop.freeze(expires_at - 10) do
        expect(verifier.valid?(message)).to eq(true)
      end
    end

    it "rejects an expired message" do
      Timecop.freeze(expires_at + 1) do
        expect(verifier.valid?(message)).to eq(false)
      end
    end
  end

  context "with a max_age" do
    let(:max_age) { 300 }

    context "relative to the 'Date' header" do
      it "verifies an unexpired message" do
        Timecop.freeze(date + max_age) do
          expect(verifier.valid?(message, max_age: max_age)).to eq(false)
        end
      end

      it "rejects an expired message" do
        Timecop.freeze(date + max_age + 1) do
          expect(verifier.valid?(message, max_age: max_age)).to eq(false)
        end
      end
    end

    context "relative to '(created)'" do
      let(:created) { 1414849472 }
      let(:expires) { 1414849972 }

      let(:signature_header) do
        'keyId="%s",algorithm="%s",headers="%s",signature="%s",created=%s,expires=%s' % [
          "pda",
          "hmac-sha256",
          "(request-target) (created)",
          "JCWhS+6Xf1eqkaAYNPcLA4A0bZrKYTWZOP/SbNMzb0g=",
          created,
          expires
        ]
      end

      it "verifies an unexpired message" do
        Timecop.freeze(date + max_age) do
          expect(verifier.valid?(message, max_age: max_age)).to eq(false)
        end
      end

      it "rejects an expired message" do
        Timecop.freeze(date + max_age + 1) do
          expect(verifier.valid?(message, max_age: max_age)).to eq(false)
        end
      end
    end
  end
end
