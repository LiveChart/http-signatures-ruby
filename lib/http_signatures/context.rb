# frozen_string_literal: true

module HttpSignatures
  class Context
    def initialize(key_store:, signing_key_id: nil, algorithm: nil, headers: nil)
      @key_store =
        case key_store
        when KeyStore
          key_store
        when Hash
          KeyStore.new(key_store)
        else
          raise ArgumentError, "Must be provided a KeyStore or Hash"
        end

      @signing_key_id = signing_key_id
      @algorithm_name = algorithm
      @headers = headers
    end

    def signer
      Signer.new(
        key: signing_key,
        algorithm: Algorithm.create(@algorithm_name),
        covered_content: CoveredContent.new(@headers),
      )
    end

    def verifier
      Verifier.new(key_store: @key_store)
    end

    private

    def signing_key
      if @signing_key_id
        @key_store.fetch(@signing_key_id)
      else
        @key_store.only_key
      end
    end
  end
end
