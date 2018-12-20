require "openssl"

require_relative "./spki"

# Additional helper methods for certificates.
#
class OpenSSL::X509::Certificate
  # Generate an OpenSSL::X509::SPKI structure for the public key in the cert.
  #
  # @param _format [NilClass] Unused.
  #
  # @return [OpenSSL::X509::SPKI]
  #
  def to_spki(_format = nil)
    OpenSSL::X509::SPKI.new(self.public_key.to_der)
  end
end
