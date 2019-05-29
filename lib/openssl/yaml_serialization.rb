require "openssl"

class OpenSSL::X509::Certificate
  def encode_with(coder)
    coder['der'] = self.to_der
  end

  def init_with(coder)
    self.__send__(:initialize, coder['der'])
  end
end

class OpenSSL::PKey::PKey
  def encode_with(coder)
    coder['der'] = self.to_der
  end

  def init_with(coder)
    self.__send__(:initialize, coder['der'])
  end
end

