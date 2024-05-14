require "openssl"

# Enhancements to the core asymmetric key handling.
module OpenSSL::PKey
  # A mapping of the "SSH" names for various curves, to their OpenSSL
  # equivalents.
  SSH_CURVE_NAME_MAP = {
    "nistp256" => "prime256v1",
    "nistp384" => "secp384r1",
    "nistp521" => "secp521r1",
  }

  # Create a new `OpenSSL::PKey` from an SSH public or private key.
  #
  # Given an OpenSSH 2 public key (with or without the `ssh-rsa` / `ecdsa-etc`
  # prefix), or an encrypted or unencrypted OpenSSH private key, create an
  # equivalent instance of an `OpenSSL::PKey::PKey` subclass which represents
  # the same key parameters.
  #
  # @param s [String] the SSH public or private key to convert.  Public keys
  #   should be in their usual all-on-one-line bas64-encoded form, with or
  #   without the key type prefix.  Private keys must have the `-----BEGIN/END
  #   OPENSSH PRIVATE KEY-----` delimiters.
  #
  # @param passphrase [String] if an encrypted private key is provided, this
  #   passphrase will be used to try and decrypt the key.  If the passphrase
  #   is incorrect, an exception will be raised.
  #
  # @yield if the key data passed is an encrypted private key and no passphrase
  #   was given, the block (if provided) will be called, and whatever the value
  #   of that block call is, it will be used to try and decrypt the private
  #   key.
  #
  # @return [OpenSSL::PKey::PKey] the OpenSSL-compatible key object.
  #
  # @raise [OpenSSL::PKey::PKeyError] if anything went wrong with the decoding
  #   process.
  #
  def self.from_ssh_key(s, &blk)
    if s =~ /\A-----BEGIN OPENSSH PRIVATE KEY-----/
      decode_private_ssh_key(s, &blk)
    else
      decode_public_ssh_key(s)
    end
  end

  # Create a new `OpenSSL::PKey` from a PuTTY private key.
  #
  # Given a PuTTY version 2 key file ("PPK"), an equivalent instance of an
  # `OpenSSL::PKey::PKey` subclass will be derived representing the same
  # key parameters.
  #
  # @param s [String] the PuTTY PPK file contents to convert.
  #
  # @yield if the key data passed is an encrypted private key, the block
  #   (if provided) will be called.
  #
  # @return [OpenSSL::PKey::PKey] the OpenSSL-compatible key object.
  #
  # @raise OpenSSL::PKey::PKeyError] if anything went wrong with the conversion
  #   process.
  #
  def self.from_putty_key(s, &blk)
    lines = s.gsub("\r\n", "\n").gsub("\r", "\n").split("\n")

    unless lines.shift =~ /\APuTTY-User-Key-File-2: ([a-z0-9-]+)\z/
      raise OpenSSL::PKey::PKeyError,
            "No PuTTY key file header found"
    end

    keytype = $1

    key = case keytype
          when 'ssh-rsa'
            OpenSSL::PKey::RSA.new
          when 'ssh-dss'
            OpenSSL::PKey::DSA.new
          when /ecdsa-sha2-/
            OpenSSL::PKey::EC.new
          else
            raise OpenSSL::PKey::PKeyError,
                  "Unknown key type #{keytype}"
          end

    unless lines.shift =~ /\AEncryption: (none|aes256-cbc)\z/
      raise OpenSSL::PKey::PKeyError,
            "Missing or invalid PuTTY Encryption line"
    end

    cipher = $1

    if cipher != "none"
      yield if block_given?
      raise OpenSSL::PKey::PKeyError,
            "Encrypted PuTTY keys are not (yet) supported"
    end

    unless lines.shift =~ /\AComment: /
      raise OpenSSL::PKey::PKeyError,
            "Missing or invalid PuTTY Comment line"
    end

    unless lines.shift =~ /\APublic-Lines: (\d+)\z/
      raise OpenSSL::PKey::PKeyError,
            "Missing or invalid PuTTY Public-Lines line"
    end

    line_count = $1.to_i

    if lines.length < line_count
      raise OpenSSL::PKey::PKeyError,
            "Invalid Public-Lines value, only #{lines.length} lines remaining in file"
    end

    pubkey = lines[0, line_count].join.unpack("m").first

    lines = lines[line_count..-1]

    unless lines.shift =~ /Private-Lines: (\d+)\z/
      raise OpenSSL::PKey::PKeyError,
            "Missing or invalid PuTTY Private-Lines line"
    end

    line_count = $1.to_i

    if lines.length < line_count
      raise OpenSSL::PKey::PKeyError,
            "Invalid Private-Lines value, only #{lines.length} lines remaining in file"
    end

    privkey = lines[0, line_count].join.unpack("m").first

    case key
    when OpenSSL::PKey::RSA
      _kt, e, n        = ssh_key_lv_decode(pubkey,  3).map { |c| ssh_key_mpi_decode(c) }
      d, p, q, iqmp, _ = ssh_key_lv_decode(privkey, 4).map { |c| ssh_key_mpi_decode(c) }

      key.set_key(n, e, d)
      key.set_factors(p, q)
      key.set_crt_params(d % (p - 1), d % (q - 1), iqmp)
    when OpenSSL::PKey::DSA
      _kt, p, q, g, y = ssh_key_lv_decode(pubkey,  5).map { |c| ssh_key_mpi_decode(c) }
      x, _            = ssh_key_lv_decode(privkey, 1).map { |c| ssh_key_mpi_decode(c) }

      key.set_key(y, x)
      key.set_pqg(p, q, g)
    when OpenSSL::PKey::EC
      _kt, curve, w = ssh_key_lv_decode(pubkey, 3)
      p, _          = ssh_key_lv_decode(privkey, 1).map { |c| ssh_key_mpi_decode(c) }

      begin
        key = OpenSSL::PKey::EC.new(SSH_CURVE_NAME_MAP[curve])
      rescue TypeError
        raise OpenSSL::PKey::PKeyError,
              "Unknown curve identifier #{curve}"
      end

      key.public_key  = OpenSSL::PKey::EC::Point.new(key.group, w)
      key.private_key = p
    end

    key
  end

  private

  def self.decode_private_ssh_key(s, &blk)
    unless s =~ /-----BEGIN OPENSSH PRIVATE KEY-----\n([A-Za-z0-9\/+\n]*={0,2})\n-----END OPENSSH PRIVATE KEY-----/m
      raise OpenSSL::PKey::PKeyError,
            "invalid OpenSSH private key format"
    end

    keyblob = unpack_private_ssh_key($1, &blk)
    keytype, rest = ssh_key_lv_decode(keyblob, 1)

    case keytype
    when "ssh-rsa"
      parts = ssh_key_lv_decode(rest, 6)
      OpenSSL::PKey::RSA.new.tap do |k|
        # n, e, d
        k.set_key(ssh_key_mpi_decode(parts[0]), ssh_key_mpi_decode(parts[1]), ssh_key_mpi_decode(parts[2]))
        # p, q
        k.set_factors(ssh_key_mpi_decode(parts[4]), ssh_key_mpi_decode(parts[5]))
        # I am mystified as to why we have to do this manually
        k.set_crt_params(k.d.to_i % (k.p.to_i - 1), k.d.to_i % (k.q.to_i - 1), ssh_key_mpi_decode(parts[3]))
      end
    when "ssh-dss"
      parts = ssh_key_lv_decode(rest, 5)
      OpenSSL::PKey::DSA.new.tap do |k|
        # Self-explanatory
        k.set_pqg(ssh_key_mpi_decode(parts[0]), ssh_key_mpi_decode(parts[1]), ssh_key_mpi_decode(parts[2]))
        # pub_key, priv_key
        k.set_key(ssh_key_mpi_decode(parts[3]), ssh_key_mpi_decode(parts[4]))
      end
    when /ecdsa-sha2-/
      parts = ssh_key_lv_decode(rest, 3)

      begin
        OpenSSL::PKey::EC.new(SSH_CURVE_NAME_MAP[parts[0]]).tap do |k|
          k.public_key = OpenSSL::PKey::EC::Point.new(k.group, parts[1])
          k.private_key = ssh_key_mpi_decode(parts[2])
        end
      rescue TypeError
        raise OpenSSL::PKey::PKeyError.new,
              "Unknown curve identifier #{parts[0]}"
      end
    else
      raise OpenSSL::PKey::PKeyError,
            "Unknown key type #{keytype}"
    end
  end

  def self.unpack_private_ssh_key(s)
    rest = s.unpack("m").first

    # From https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD

    #  8: #define AUTH_MAGIC      "openssh-key-v1"
    #  9:
    # 10:        byte[]  AUTH_MAGIC
    unless rest[0, 15] == "openssh-key-v1\0"
      raise OpenSSL::PKey::PKeyError,
            "Invalid OpenSSH private key: incorrect magic found (#{rest[0, 15].inspect})"
    end

    # 11:        string  ciphername
    # 12:        string  kdfname
    # 13:        string  kdfoptions
    cipher, kdf, kdfopts, rest = ssh_key_lv_decode(rest[15..], 3)

    # 14:        int     number of keys N
    key_count, rest = rest.unpack("Na*")
    if key_count == 0
      raise OpenSSL::PKey::PKeyError,
            "invalid OpenSSH private key: no keys!"
    elsif key_count > 1
      raise OpenSSL::PKey::PKeyError,
            "unsupported OpenSSH private key: multiple keys"
    end

    # 15:        string  publickey1
    # We care not for your stinky public key
    _, rest = ssh_key_lv_decode(rest, 1)

    # 19:        string  encrypted, padded list of private keys
    rest, x = ssh_key_lv_decode(rest, 1)
    unless x.nil?
      #:nocov:
      raise OpenSSL::PKey::PKeyError,
            "invalid OpenSSH private key: trailing garbage after private key blob: #{x.inspect}"
      #:nocov:
    end

    if kdf == "none"
      # This one is easy
      # 36:        uint32  checkint
      # 37:        uint32  checkint
      # 38:        string  privatekey1
      check1, check2, rest = rest.unpack("NNa*")
      unless check1 == check2
        raise OpenSSL::PKey::PKeyError,
              "invalid OpenSSH private key: check values don't match"
      end

      # The format spec says that the keyblob is, itself, a string, but that's
      # not what I'm seeing in real-world keys generated by OpenSSH -- the
      # first element of the keyblob (the key type string) is just straight up
      # there after the check digits.  That must make parsing out multiple
      # private keys an absolute nightmare -- except, oh wait (from
      # openssh-portable.git/sshkey.c):
      #
      #     if (nkeys != 1) {
      #         /* XXX only one key supported */
      #         r = SSH_ERR_INVALID_FORMAT;
      #         goto out;
      #     }
      #
      # Cheaters.
      #
      # At any rate, the fact that the spec isn't what's implemented means that
      # the keyblob I do send back needs to be carefully parsed itself, rather
      # than just being able to blat it through ssh_key_lv_decode to get all
      # the bits.  Sigh.
      return rest
    elsif kdf == "bcrypt"
      # This is cheating a little bit, but I'm not up for implementing
      # decryption support today, and this at least allows us to reliably
      # detect that the key *is* in fact encrypted rather than corrupted
      yield if block_given?
      raise OpenSSL::PKey::PKeyError,
            "unsupported OpenSSH private key: decryption is not (yet) supported"
    else
      raise OpenSSL::PKey::PKeyError,
            "unsupport OpenSSH private key KDF #{kdf.inspect}"
    end
  end

  def self.decode_public_ssh_key(s)
    if s =~ /\A(sk-)?(ssh|ecdsa)-/
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

    parts = ssh_key_lv_decode(s.unpack("m").first)

    case parts.first
    when "ssh-rsa"
      e = ssh_key_mpi_decode(parts[1])
      n = ssh_key_mpi_decode(parts[2])

      # OpenSSL 3.0 stole our set_key, so we now have to play silly DER round-trip games... sigh
      OpenSSL::PKey.read(
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("rsaEncryption"),
            OpenSSL::ASN1::Null.new(nil),
          ]),
          OpenSSL::ASN1::BitString.new(
            OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::Integer.new(n),
              OpenSSL::ASN1::Integer.new(e),
            ]).to_der
          ),
        ]).to_der
      )
    when /ecdsa-sha2-/
      curve_name = SSH_CURVE_NAME_MAP[parts[1]]
      if curve_name.nil?
        raise OpenSSL::PKey::PKeyError.new, "Unknown curve identifier #{parts[1]}"
      end
      point = parts[2]

      # OpenSSL 3.0 stole our set_key, so we now have to play silly DER round-trip games... sigh
      OpenSSL::PKey.read(
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
            OpenSSL::ASN1::ObjectId.new(curve_name),
          ]),
          OpenSSL::ASN1::BitString.new(point),
        ]).to_der
      )
    when "ssh-ed25519", "sk-ssh-ed25519@openssh.com"
      # The Ruby OpenSSL bindings don't appear to provide a way to directly construct
      # an ed25519 key from its parts; instead, we've got to encode our own public key
      # DER and then get OpenSSL to read it.  Thankfully, ed25519 keys aren't too
      # complicated to construct in DER.
      OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("ED25519")]), OpenSSL::ASN1::BitString.new(parts[1])]).to_der)
    else
      raise OpenSSL::PKey::PKeyError,
            "Unsupported key type #{parts.first.inspect}"
    end
  end

  # Take the base64 string and split it into its component parts.
  #
  def self.ssh_key_lv_decode(s, n = nil)
    rest = s

    [].tap do |parts|
      until rest == "" || (n && n <= 0)
        len, rest = rest.unpack("Na*")
        if len > rest.length
          raise OpenSSL::PKey::PKeyError,
                "Invalid LV-encoded string; wanted #{len} octets, but there's only #{rest.length} octets left"
        end

        elem, rest = rest.unpack("a#{len}a*")
        parts << elem
        n -= 1 if n
      end

      if rest != ""
        parts << rest
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
