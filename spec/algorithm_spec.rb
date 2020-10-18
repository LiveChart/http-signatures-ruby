# frozen_string_literal: true

require "base64"

RSpec.describe HttpSignatures::Algorithm do
  let(:key) { "the-key" }
  let(:input) { "the string\nto sign" }

  {
    "hs2019" => "bXPeVc5ySIyeUapN7mpMsJRnxVg="
  }.each do |name, base64_signature|
    describe ".create('#{name}')" do
      let(:algorithm) { HttpSignatures::Algorithm.create(name) }

      it "has #name == '#{name}'" do
        expect(algorithm.name).to eq(name)
      end

      # it "produces known-good signature" do
      #   signature = algorithm.sign(key, input)
      #   expect(signature).to eq(Base64.strict_decode64(base64_signature))
      # end
    end
  end

  it "raises error for unknown algorithm" do
    expect {
      HttpSignatures::Algorithm.create(name: "nope", key: nil)
    }.to raise_error(HttpSignatures::Algorithm::UnknownAlgorithm)
  end
end
