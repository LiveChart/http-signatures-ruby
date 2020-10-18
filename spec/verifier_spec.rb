# frozen_string_literal: true

require "net/http"
require "time"

RSpec.describe HttpSignatures::Verifier do

  DATE = "Fri, 01 Nov 2014 13:44:32 GMT"
  DATE_DIFFERENT = "Fri, 01 Nov 2014 13:44:33 GMT"

  let(:date) { Time.httpdate(DATE) }

  let(:created) { nil }
  let(:expires) { nil }

  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa.pub"))) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, "keys", "id_rsa"))) }

  subject(:verifier) { HttpSignatures::Verifier.new(key_store: key_store) }
  let(:key_store) do
    HttpSignatures::KeyStore.new({
      "pda" => {
        private_key: private_key,
        public_key: public_key,
      }
    })
  end
  let(:http_message) { Net::HTTP::Get.new("/path?query=123", headers) }
  let(:message) { HttpSignatures::Message.from(http_message) }
  let(:headers) { { "Date" => DATE, "Signature" => signature_header } }

  let(:signature_header) do
    'keyId="%s",algorithm="%s",headers="%s",signature="%s"' % [
      "pda",
      "hs2019",
      "(request-target) date",
      "I9q+MqAUhjPqJSvSjWpxEx3wftzyycqXoeGLeVUSeMr1bLJlnpFA007HH/7UjnoZr/Ufex1rw6JQf4FA5k8wXTFa7qJfG26Tguj1grMqrXFgjjJOcE3llhoJSBMyXTU7PjDOZ13c9b9Y7U1jJIkGOACEFLOQktCQt3HtTtcXgtQ=",
    ]
  end

  # Generate a signature
  # it do
  #   HttpSignatures::Context.new(
  #     key_store: key_store,
  #     signing_key_id: "pda",
  #     algorithm: "hs2019",
  #     headers: %w[(request-target) date]
  #   ).signer.sign(http_message, expires: expires, created: created)
  #   puts http_message["Signature"]
  # end

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
        "hs2019",
        "(request-target) (expires)",
        "FlOGGPAfuUfDZ44ApquserAFVa9fXNymH78MWbNMwvbggn4Z+FXs5FElXI2M0fqFj98UwdGMaQp9toKFKMbtWGWn0URf/3akMP3Ih0cgKIRQZEvOudgQhEgRglaXUI2wA3eArJYJq+KF4Cb+Asbmqsk8pC5Zo0NyiBEvH1Y1FeM=",
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
          "hs2019",
          "(request-target) (created)",
          "EpLw3xdjllE/k2KLM+ZTfrG6eLW1I1S8TMoU5KejWvCXyOKVxJbaEUBgD7rnuana9xTK/+UMeCXRthOegCqFuLNsRoMXgxqgZr9naeYzdhdN3b+Y8eFxNfNHAAUsAFpO2cbxKLqaVrDueZByXzXkQc5xhGuU+udlEj7w1ZPCfTs=",
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
