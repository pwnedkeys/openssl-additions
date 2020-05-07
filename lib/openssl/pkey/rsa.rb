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

  # Construct a fully-featured RSA private key from fundamental values.
  #
  # Many parts of an RSA key are, in fact, derived from the basic numbers that
  # are (mostly) generated randomly.  Whilst it is always better to let OpenSSL
  # generate a whole key for you, in *extremely* limited circumstances, it can
  # be useful to get a key which has been populated using factors derived from
  # another source.
  #
  # @note This method does not attempt to validate that the values for `p` & `q`
  #   are, in fact, primes, nor does it make any value judgments about your
  #   choice of `e`.
  #
  # @param p [Integer] the larger of the two prime numbers that comprise the
  #   fundamental RSA private key.
  #
  # @param q [Integer] the smaller of the two prime numbers.
  #
  # @param e [Integer] the public exponent used by the key.
  #
  # @return [OpenSSL::PKey::RSA]
  #
  # @raise [OpenSSL::PKey::PKeyError]
  #
  def self.from_factors(p, q, e)
    p, q = q, p if p < q

    n = p * q
    # While `lcm = (p - 1).lcm(q - 1)` produces smaller keys, this version
    # produces key that are identical to OpenSSL, which is generally our
    # compatibility target.
    lcm = (p - 1) * (q - 1)

    if e < 1 || e >= lcm
      raise OpenSSL::PKey::PKeyError,
            "e must be 1 < e < lambda(n)"
    end

    if e.gcd(lcm) != 1
      raise OpenSSL::PKey::PKeyError,
            "e must coprime to lambda(n)"
    end

    d, _ = egcd(e, lcm)
    # Ensure that d > 0
    d %= lcm if d < 0

    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp, _ = egcd(q, p)

    iqmp += p / p.gcd(q) if iqmp < 0

    OpenSSL::PKey::RSA.new.tap do |k|
      k.set_key(n, e, d)
      k.set_factors(p, q)
      k.set_crt_params(dmp1, dmq1, iqmp)
    end
  end

  private

  def self.egcd(a, b)
    return 1, 0 if b == 0

    q, r = a.divmod b
    s, t = egcd(b, r)

    [t, s - q * t]
  end
end
