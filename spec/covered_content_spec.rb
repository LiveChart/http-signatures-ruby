# frozen_string_literal: true

RSpec.describe HttpSignatures::CoveredContent do
  describe ".from_string" do
    it "loads and normalizes header names" do
      expect(HttpSignatures::CoveredContent).to receive(:new).with(
        ["(request-target)", "Date", "Content-Type", "(created)", "(expires)"]
      )
      HttpSignatures::CoveredContent.from_string(
        "(request-target) Date Content-Type (created) (expires)"
      )
    end
  end

  describe ".new" do
    it "normalizes header names (downcase)" do
      list = HttpSignatures::CoveredContent.new(["(request-target)", "Date", "Content-Type", "(created)", "(expires)"])
      expect(list.to_a).to eq(["(request-target)", "date", "content-type", "(created)", "(expires)"])
    end

    %w[Signature].each do |header|
      it "raises IllegalHeader for #{header} header" do
        expect {
          HttpSignatures::CoveredContent.new([header])
        }.to raise_error(HttpSignatures::CoveredContent::IllegalHeader)
      end
    end
  end

  describe "#to_s" do
    it "joins normalized header names with spaces" do
      list = HttpSignatures::CoveredContent.new(["(request-target)", "Date", "Content-Type", "(created)", "(expires)"])
      expect(list.to_s).to eq("(request-target) date content-type (created) (expires)")
    end
  end
end
