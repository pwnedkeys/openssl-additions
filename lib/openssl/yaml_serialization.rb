require "openssl"

module OpenSSL::YamlSerialization
  module DER
    def encode_with(coder)
      coder['der'] = self.to_der
    end

    def init_with(coder)
      self.__send__(:initialize, coder['der'])
    end
  end
end

OpenSSL::X509::Certificate.prepend(OpenSSL::YamlSerialization::DER)
OpenSSL::X509::Name.prepend(OpenSSL::YamlSerialization::DER)
OpenSSL::PKey::PKey.prepend(OpenSSL::YamlSerialization::DER)
