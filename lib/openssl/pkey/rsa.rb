require "openssl"

require_relative "../x509/spki"

# Additional helper methods for RSA keys.
#
class OpenSSL::PKey::RSA
  # Generate an OpenSSL::X509::SPKI structure for this public key.
  #
  # @param _format [NilClass] unused by this class.
  #
  # @return [OpenSSL::X509::SPKI]
  #
  def to_spki(_format = nil)
    OpenSSL::X509::SPKI.new(self.public_key.to_der)
  end
end
