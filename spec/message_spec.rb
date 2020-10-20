# frozen_string_literal: true

require "net/http"
require "action_dispatch"
require "action_dispatch/testing/test_request"

RSpec.describe HttpSignatures::Message do
  let(:instance) { described_class.new(path: path_arg, verb: verb_arg, headers: headers_arg) }
  let(:path_arg) { "/Test.php" }
  let(:verb_arg) { "GET" }
  let(:headers_arg) { { "Digest" => "aBc" } }

  describe ".from" do
    let(:path) { "/from-test.html" }
    let(:parsed) { described_class.from(request) }

    context "provided an ActionDispatch::Request" do
      let(:request) do
        ActionDispatch::TestRequest.create({
          "REQUEST_METHOD" => "DELETE",
          "PATH_INFO" => path,
          "Digest" => "actionREQUEST"
        })
      end

      it "correctly parses the path" do
        expect(parsed.path).to eq("/from-test.html")
      end

      it "correctly parses the verb" do
        expect(parsed.verb).to eq("delete")
      end

      it "correctly parses the headers" do
        expect(parsed.headers).to include("digest" => "actionREQUEST")
      end
    end

    context "provided a net/http request" do
      let(:request) do
        Net::HTTP::Get.new(
          path,
          "Digest" => "netHTTPrequest"
        )
      end

      it "correctly parses the path" do
        expect(parsed.path).to eq("/from-test.html")
      end

      it "correctly parses the verb" do
        expect(parsed.verb).to eq("get")
      end

      it "correctly parses the headers" do
        expect(parsed.headers).to include("digest" => "netHTTPrequest")
      end
    end
  end

  describe ".new" do
    it "does not raise when provided valid values" do
      expect { instance }.not_to raise_error
    end

    it "normalizes the verb" do
      expect(instance.verb).to eq("get")
    end

    it "does not change the path" do
      expect(instance.path).to eq("/Test.php")
    end

    context "provided headers with capitalized names" do
      let(:headers_arg) { { "Digest" => "aBc" } }

      it "normalizes the headers" do
        expect(instance.headers).to eq({ "digest" => "aBc" })
      end
    end

    context "provided duplicate headers" do
      let(:headers_arg) { { "Digest" => ["aBc", "dEF"] } }

      it "normalizes the headers" do
        expect(instance.headers).to eq({ "digest" => "aBc, dEF" })
      end
    end
  end

  describe "#request_target" do
    it { expect(instance.request_target).to eq("get /Test.php") }
  end

  describe "#headers" do
    it "returns a duplicate hash" do
      expect { instance.headers["test"] = "true" }.not_to change { instance.header("test") }
    end
  end

  describe "#header?" do
    it "checks for presence ignoring case" do
      expect(instance.header?("DiGESt")).to eq(true)
    end

    it "identifies missing headers" do
      expect(instance.header?("Authorization")).to eq(false)
    end
  end

  describe "#header" do
    it "checks for presence ignoring case" do
      expect(instance.header("DiGESt")).to eq("aBc")
    end

    it "identifies missing headers" do
      expect(instance.header("Authorization")).to eq(nil)
    end
  end

  describe "#header!" do
    it "checks for presence ignoring case" do
      expect(instance.header!("DiGESt")).to eq("aBc")
    end

    it "identifies missing headers" do
      expect { instance.header!("Authorization") }.to raise_error HttpSignatures::Message::MissingHeaderError
    end
  end
end
