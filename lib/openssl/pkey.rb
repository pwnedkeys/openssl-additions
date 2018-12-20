require "openssl"

# Enhancements to the core asymmetric key handling.
module OpenSSL::PKey
  # A mapping of the "SSH" names for various curves, to their OpenSSL
  # equivalent names.
  SSH_CURVE_NAME_MAP = {
    "nistp256" => "prime256v1",
    "nistp384" => "secp384r1",
    "nistp521" => "secp521r1",
  }

  # Create a new `OpenSSL::PKey` from an SSH public key.
  #
  # Given an OpenSSL 2 public key (with or without the `ssh-rsa` / `ecdsa-etc`
  # prefix), create an equivalent instance of an `OpenSSL::PKey::PKey` subclass
  # which represents the same key parameters.
  #
  # If you've got an SSH *private* key, you don't need this method, as they're
  # already PKCS#8 ("PEM") private keys, which OpenSSL is happy to read
  # directly (using `OpenSSL::PKey.read`).
  #
  # @param s [String] the SSH public key to convert, in its usual
  #   base64-encoded form, with or without key type prefix.
  #
  # @return [OpenSSL::PKey::PKey] the OpenSSL-compatible key object.  Note
  #   that this can only ever be a *public* key, never a private key, because
  #   SSH public keys are, well, public.
  #
  def self.from_ssh_key(s)
    if s =~ /\Assh-[a-z0-9-]+ /
      # WHOOP WHOOP prefixed key detected.
      s = s.split(" ")[1]
    else
      # Discard any comment, etc that might be lurking around
      s = s.split(" ")[0]
    end

    unless s =~ /\A[A-Za-z0-9\/+]+={0,2}\z/
      raise OpenSSL::PKey::PKeyError,
            "Invalid key encoding (not valid base64)"
    end

    parts = ssh_key_lv_decode(s)

    case parts.first
    when "ssh-rsa"
      OpenSSL::PKey::RSA.new.tap do |k|
        k.e = ssh_key_mpi_decode(parts[1])
        k.n = ssh_key_mpi_decode(parts[2])
      end
    when "ssh-dss"
      OpenSSL::PKey::DSA.new.tap do |k|
        k.p = ssh_key_mpi_decode(parts[1])
        k.q = ssh_key_mpi_decode(parts[2])
        k.g = ssh_key_mpi_decode(parts[3])
      end
    when /ecdsa-sha2-/
      begin
        OpenSSL::PKey::EC.new(SSH_CURVE_NAME_MAP[parts[1]]).tap do |k|
          k.public_key = OpenSSL::PKey::EC::Point.new(k.group, parts[2])
        end
      rescue TypeError
        raise OpenSSL::PKey::PKeyError.new,
              "Unknown curve identifier #{parts[1]}"
      end
    else
      raise OpenSSL::PKey::PKeyError,
            "Unknown key type #{parts.first.inspect}"
    end
  end

  private

  # Take the base64 string and split it into its component parts.
  #
  def self.ssh_key_lv_decode(s)
    rest = s.unpack("m").first

    [].tap do |parts|
      until rest == ""
        len, rest = rest.unpack("Na*")
        if len > rest.length
          raise OpenSSL::PKey::PKeyError,
                "Invalid LV-encoded string; wanted #{len} octets, but there's only #{rest.length} octets left"
        end

        elem, rest = rest.unpack("a#{len}a*")
        parts << elem
      end
    end
  end

  # Turn an SSH "MPI" (encoded arbitrary-length integer) string into a real
  # Ruby integer.
  #
  def self.ssh_key_mpi_decode(s)
    s.each_char.inject(0) { |i, c| i * 256 + c.ord }
  end
end
