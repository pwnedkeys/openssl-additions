require_relative "../spec_helper"

require "openssl/yaml_serialization"
require "yaml"

describe OpenSSL::X509::Certificate do
  let(:test_cert) do
    <<~EOF
      -----BEGIN CERTIFICATE-----
      MIIBCjCBtaADAgECAgEBMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNVBAMMA2JvYjAe
      Fw03MDAxMDEwMDAwMDBaFw03MDAxMDEwMDAwMDBaMA4xDDAKBgNVBAMMA2JvYjBc
      MA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDxFMHb0KF8Hiu3tIGTzvNtIUEpzrzQHiVo
      CsVYQ6mSO5FyX2HzuuyCBRR3F9wn1VNUSjf99EXdVPLCvAEj4FdLAgMBAAEwDQYJ
      KoZIhvcNAQELBQADQQB1y1pwjc+zT5oDvD7HsBsc4AASHgTON2FNsg/oWbaPKDkq
      IW3PkU7p2QPPy4z4y5lycTvv9RQgBanKlI2gUx84
      -----END CERTIFICATE-----
    EOF
  end

  describe "#to_yaml" do
    it "round-trips a certificate correctly" do
      cert = YAML.load(OpenSSL::X509::Certificate.new(test_cert).to_yaml)

      expect(cert.issuer.to_s).to eq("/CN=bob")
    end
  end
end

describe OpenSSL::PKey::RSA do
  let(:test_key) { OpenSSL::PKey::RSA.new(1024) }

  describe "#to_yaml" do
    it "round-trips a key correctly" do
      key = YAML.load(test_key.to_yaml)

      expect(key.n).to eq(test_key.n)
    end
  end
end

describe OpenSSL::PKey::EC do
  let(:test_key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

  describe "#to_yaml" do
    it "round-trips a key correctly" do
      key = YAML.load(test_key.to_yaml)

      expect(key.public_key).to eq(test_key.public_key)
    end
  end
end
