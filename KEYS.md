## RSA

```ruby
key = OpenSSL::PKey::RSA.new(2048)

key.to_pem # Private key PEM
key.public_key.to_pem # Public key PEM
```

## ECDSA

```ruby
ec_domain_key, ec_public = OpenSSL::PKey::EC.new("prime256v1"), OpenSSL::PKey::EC.new("prime256v1")
ec_domain_key.generate_key
ec_public.public_key = ec_domain_key.public_key

ec_domain_key.to_pem # Private key PEM
ec_public.to_pem # Public key PEM
```