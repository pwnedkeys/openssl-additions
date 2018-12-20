require "openssl"

require_relative "../x509/spki"

# Additional helpers for ECDSA keys.
#
class OpenSSL::PKey::EC
  # Generate an OpenSSL::X509::SPKI structure for this public key.
  #
  # @param format [Symbol] whether to return the SPKI containing the compressed
  #   or uncompressed form of the curve point which represents the public key.
  #   Note that from a functional perspective, the two forms are identical, but
  #   they will produce completely different key and SPKI fingerprints, which
  #   may be important.
  #
  # @return [OpenSSL::X509::SPKI]
  #
  def to_spki(format = :uncompressed)
    unless self.public_key?
      raise OpenSSL::PKey::ECError,
            "Cannot convert non-public-key to SPKI"
    end
    OpenSSL::X509::SPKI.new("id-ecPublicKey", OpenSSL::ASN1::ObjectId.new(self.public_key.group.curve_name), self.public_key.to_octet_string(format))
  end
end
