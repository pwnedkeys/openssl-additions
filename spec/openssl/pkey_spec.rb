require_relative "../spec_helper"

require "openssl/pkey"

describe OpenSSL::PKey do
  describe "#from_ssh_key" do
    let(:pkey) { OpenSSL::PKey.from_ssh_key(ssh_key) }

    context "given an RSA key with a prefix" do
      let(:ssh_key) do
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCZI+gzukzJkpokvvIIpVkh2K0G2gDv" +
        "JKBjnj4nDzkOqbqQrNxZ+MNJy5/z4HcA2Mbi8hcKJMUWJW/JMrwTzm8jDkDvYITdsy22" +
        "60m0Up84ySlFlgGwB73jZuGnrf6Lbe2X9+P5H3h/3JpJ0+OxoRjqWYerKaWJF/wVFlqe" +
        "bYl8bw=="
      end

      it "returns an RSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::RSA)
      end

      it "returns the *correct* RSA key" do
        expect(pkey.e).to eq(65537)
      end
    end

    context "given an RSA key without a prefix" do
      let(:ssh_key) do
        "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCZI+gzukzJkpokvvIIpVkh2K0G2gDvJKBjnj4n" +
        "DzkOqbqQrNxZ+MNJy5/z4HcA2Mbi8hcKJMUWJW/JMrwTzm8jDkDvYITdsy2260m0Up84" +
        "ySlFlgGwB73jZuGnrf6Lbe2X9+P5H3h/3JpJ0+OxoRjqWYerKaWJF/wVFlqebYl8bw==" +
        " arglefargle"
      end

      it "returns an RSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::RSA)
      end

      it "returns the *correct* RSA key" do
        expect(pkey.e).to eq(65537)
      end
    end

    context "given a DSA key" do
      let(:ssh_key) do
        # Wow I'd forgotten how huge DSS keys are...
        "AAAAB3NzaC1kc3MAAACBAM6PC9FHvwGP8i5XC650aQEFOefh3PA9/OuAi5YeJ2xL02FA" +
        "04uaceUKcjecr5zKktmPDGSK9YbsmHcMUazTuEXu6GGguR08YfD12AtKDcS/7DDFHZtM" +
        "Dfy4ZovuOuk3NB76205swbUsBi6qElfKFgJ+e591MqgycDm0wYnasntVAAAAFQDQOURk" +
        "LrRktUEsJlMdKMVy53SSRwAAAIEAvdzwLbh/cMHz92cOodF6TSZKiEAX5qtKgWyL+zKX" +
        "nS3vbrcI1Y5alMb2VRSNm1dYEX4CY/XdsO+4Sxyv0CpXWf391bW0b+vE6vj660+yoGwe" +
        "HcebuPDpCr6xckWdlwuL9NIxvStB8pkMJ+9Xb9RVJYALAcIM3h0NVOvaRp70iSYAAACA" +
        "eHdzuTojgJSc0zjGqER/mfMWS3Id+H7JmwFIGBw1oaVDoBN8OlE+QHxaMSR2Vwo8smmp" +
        "aZ9KQfsOEE4f0y+9+H+mysJEQQzdYLYW6jjQEs1VSbLwgyZiWQyghtx4IMvcYjy1Ou7L" +
        "+dgTkCETBY43OhxOsyxFB9EIWdW4rZsvIEE="
      end

      it "returns a DSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::DSA)
      end
    end

    context "given a P-256 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP8bNZ1mT+YVRO5k" +
        "OGtyvhIgfV/WgpuLE8znAxYdXcBxyrl3wJH4gW0ynwiwiDRwC6PwPfiAqUvt4oJ/2AXR" +
        "Ei0="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("prime256v1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a P-384 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBBat9t51O7ISnZP" +
        "8fyOpC/EjxYaqxeAinUolYXihvfLKwylHiZCscziD2/A4Cl/0F7sKjsQcYSJxJPM73D4" +
        "4sVP5yjSytpm6GZNAUlbGIL2J/HOo3afITbk60uWmMxVpw=="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("secp384r1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a P-521 EC key" do
      let(:ssh_key) do
        "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHFtMbDFx9QH+qQ" +
        "014JZSI8VyfTPe1XKj23w6IorpOikQEETSuBsIGF4fMoP4xrLU6II8w2qi50F2xwPHNh" +
        "2v9xtgBJO0aNKv06igUD1fDeNgrl34feCd6IsIRVKyjt493tYl0jd5YzYPEh2gnT/xPd" +
        "g2aQHcPjtx3qwWOm7C2UkJGmMw=="
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns the right curve" do
        expect(pkey.group.curve_name).to eq("secp521r1")
      end

      it "returns a valid public key" do
        expect(pkey).to be_public
      end
    end

    context "given a mystery curve EC key" do
      let(:ssh_key) do
        ["\x00\x00\x00\x13ecdsa-sha2-nistp666" +
         "\x00\x00\x00\x08nistp666" +
         "\x00\x00\x00\x05ohai!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /nistp666/)
      end
    end

    context "given a key of some mystery type" do
      let(:ssh_key) do
        ["\x00\x00\x00\x0Assh-lolrus\x00\x00\x00\x05ohai!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /ssh-lolrus/)
      end
    end

    context "given a key that isn't valid base64" do
      let(:ssh_key) { "notbase64!!!" }

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end

    context "given a LV stanza with an out-of-bounds length" do
      let(:ssh_key) do
        ["\x00\x00\x00\xFFthis isn't 256 characters long!"].pack("m")
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end

    context "given an unencrypted RSA private key" do
      let(:ssh_key) do
        <<~EOK
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAIEAoPYsEA6VM1V3EjzpFlQ4fJGWxppHZaSABqkma8RYl/iwQ6fwANer
        cMSC6xXhC9zQBDvQ8T/xO2nSzCRTgpHxL7trzjePuWi6KL6KWkmcL+v8U+naAiunHUTIsI
        Y6+dXFEHn/9voxmNNRYFfw7ugx7SyPUDmSSmMFHIENvLlZF8cAAAH4QltfQ0JbX0MAAAAH
        c3NoLXJzYQAAAIEAoPYsEA6VM1V3EjzpFlQ4fJGWxppHZaSABqkma8RYl/iwQ6fwANercM
        SC6xXhC9zQBDvQ8T/xO2nSzCRTgpHxL7trzjePuWi6KL6KWkmcL+v8U+naAiunHUTIsIY6
        +dXFEHn/9voxmNNRYFfw7ugx7SyPUDmSSmMFHIENvLlZF8cAAAADAQABAAAAgDBomOvjVt
        /vbjYf94HtpmdgadYlBB//jzlxmcqDbJmYA3r1gOrf8gGiODV3iQ1GRZFgZACKWISj2O/o
        ZO058y0Lq1cCKVSkqTp9pjonBtBougpm/117dqBP5jyz8RhMnus97Ct5jixD+gkfO9QBfb
        R9UT3Qk8nwXqz4eAyXtevxAAAAQCVpuDHW6JuVhWr6jPHIVnx2GE/45CNK7ytjRtvOT2Wj
        51ntQ7xp1CFsbi0AyLozzJoD7Abm289Tq0ro6vjeFTUAAABBANEesaINXpRccz/E5+dWxM
        r8F3A27YLsxxYrm4kOsizVF/YqpMggax11mK1/Rg1DtB5IGlYjl20MarPCEvSNVTUAAABB
        AMULsZEQErFF84rDXwp7xNu3H4y0+O5lWAuq+MAAJHcZK+lvhr/7cDwTdaq+TPVnj2OQI2
        U3iz2OHvDldQoLBIsAAAAAAQID
        -----END OPENSSH PRIVATE KEY-----
        EOK
      end

      it "returns an RSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::RSA)
      end

      it "returns a *private* key" do
        expect(pkey).to be_private
      end

      it "has sensible values" do
        expect(pkey.e.to_i).to eq(65537)
        expect(pkey.n.to_i).to eq(pkey.p.to_i * pkey.q.to_i)
      end
    end

    context "given an unencrypted DSA private key" do
      let(:ssh_key) do
        <<~EOK
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
        NzAAAAgQCJtgY45yKe48SlPkyVS+nHRB2eQjlR/uVYU3TH28sHsm1M2LM3ZjZ5enNatMc4
        /Sfe8l0dERNMGX0FXsPAlexHvJtHxhWsDO79XLkHuK+NGr+DdSwt2nUMBvYZL5EwZSttif
        o7KjSJ6HOLfuEKyWJ9Yj53Mjua/vEM4yvcGWACyQAAABUAmoSE/osjrL3R8n6h2E9OKxbg
        /8cAAACAX39Rp34aJVhFA5YsX1MMd1vu9hGq8ykXkaXhkFYQqZq8KZ1Pp4zzRIZVhWX8sP
        XyHQ9Qu26o3cQUi2v8WIH2DwgYrHen9LU1xVUtg1QqCwaihYy+ap2vO8Y1g42ujKiHVHRU
        BeEYLtGEVpPeS8nU+fEhQAmksumNWQXh6g3zIM4AAACAflEWE1fmfEeZztnox1l8SlAY9i
        4uG0vwWlmKvD7WhAy+PQs/vnhvdmMqFc5x9AJkOmFf6/w+SEDUpp9ltXIKLkQmBvhK2B2O
        gtpSSQ5thk4v6LACADxRSUQOmMDIeskN4S4oEVg14EKmcAfqiVXBVy61o9Azif34uprK9l
        oWcLoAAAHYYeoHoWHqB6EAAAAHc3NoLWRzcwAAAIEAibYGOOcinuPEpT5MlUvpx0QdnkI5
        Uf7lWFN0x9vLB7JtTNizN2Y2eXpzWrTHOP0n3vJdHRETTBl9BV7DwJXsR7ybR8YVrAzu/V
        y5B7ivjRq/g3UsLdp1DAb2GS+RMGUrbYn6Oyo0iehzi37hCslifWI+dzI7mv7xDOMr3Blg
        AskAAAAVAJqEhP6LI6y90fJ+odhPTisW4P/HAAAAgF9/Uad+GiVYRQOWLF9TDHdb7vYRqv
        MpF5Gl4ZBWEKmavCmdT6eM80SGVYVl/LD18h0PULtuqN3EFItr/FiB9g8IGKx3p/S1NcVV
        LYNUKgsGooWMvmqdrzvGNYONroyoh1R0VAXhGC7RhFaT3kvJ1PnxIUAJpLLpjVkF4eoN8y
        DOAAAAgH5RFhNX5nxHmc7Z6MdZfEpQGPYuLhtL8FpZirw+1oQMvj0LP754b3ZjKhXOcfQC
        ZDphX+v8PkhA1KafZbVyCi5EJgb4StgdjoLaUkkObYZOL+iwAgA8UUlEDpjAyHrJDeEuKB
        FYNeBCpnAH6olVwVcutaPQM4n9+LqayvZaFnC6AAAAFHxp7c1IQ5n7HRVoaJmHSMMQzi8v
        AAAAAAECAw==
        -----END OPENSSH PRIVATE KEY-----
        EOK
      end

      it "returns a DSA key" do
        expect(pkey).to be_an(OpenSSL::PKey::DSA)
      end

      it "returns a *private* key" do
        expect(pkey).to be_private
      end
    end

    context "given an unencrypted ECDSA private key" do
      let(:ssh_key) do
        <<~EOK
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQT4GwvSK80LgIYPdL7KpjE69GTgzb6
        uzYgVHSOBhHmmN+VqSwAMkeFV/TNBjeu71L/brSwC4gXsE3wQNvzzVoRAAAAoN/qgIPf6o
        CDAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBPgbC9IrzQuAhg9
        0vsqmMTr0ZODNvq7NiBUdI4GEeaY35WpLAAyR4VX9M0GN67vUv9utLALiBewTfBA2/PNWh
        EAAAAhAIKKJIfBZIbfshRrxjGfcU75b+Mnt+fqPWGTpahE6JJNAAAAAAECAwQFBgc=
        -----END OPENSSH PRIVATE KEY-----
        EOK
      end

      it "returns an EC key" do
        expect(pkey).to be_an(OpenSSL::PKey::EC)
      end

      it "returns a *private* key" do
        expect(pkey).to be_private
      end
    end

    context "given an encrypted private key" do
      let(:ssh_key) do
        <<~EOK
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBC8AcUDA
        HZ+BL9NEsp4BkfAAAAEAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQC68C+nUAW9
        ab6u2t/caV5ptzkBe2ENYsfasYn5UCqH8ZpQ4iD6WsNMBeSUD7Plk1KdOas7QlR4rbIPdA
        khm24OIMw5xDZKgRmkZo2wll8heCYSNVZz75HcCH0MMpzcON5lT7tkEOCHzZ4kbV1vxkAK
        5eNec5SFVE9NRKtMDvWKswAAAgCMqGX/Y3ENiHv5WDp3Uj5Ms5J8aR42LnW4yS0lsTX1XE
        LRI+PJjMkFpTJE+KwbgedlCtADjY8Ocmm9DP0MAjIQWGT8iKQAdowmlRlJ62LzShp2rrt8
        mj0tUjAkbPCdOo8XxGRerib7yxOa0uCV3ljGOIhNm6kCWcyg4TFMRcZzhic0IowjJiFgRS
        XtH4w+1VAbSfZEQPUGwih607NqajebYiycGpvHAPCxxJXfIq3N2/QDWj1mFEoS2EbRznUn
        7sdggdhDmkEmqOMMN6ZTe3jZevEUNk+4dWfQf25fF73V3PLGIIvV+0eH/+obS13QMwDC9g
        qmPibFVvzFAVEOBb61+S4B7JILETnxnZwAr9X5XEmCpAbGYhxJQX4QZbheNVtt97rNo4g0
        9R/vodNEUpl2uMGpgFrJwcP0l9dNu89gCEQNGeu1V1WeZElitCa97bnEOU6WhbOvHxxPy5
        pWU4yJiv/BNTdM0LGwcbexL6aMHw1iqW47ZVowkZ67f4pxFQBaLskIN1L8YUSxvMrFvkLC
        fcrbt546N/+6hT3tbWewH1sR18tGHI6wFx6iAjurXHM1OXVncNxkygx+qEu6p3vQD+hYKP
        U0W6cY3Ykabo4EPQtXeq0ZQoRWiOzkCK6PcBr32p9/bNyHOE0dhn3aBlDKumTeXHjX1TJA
        YA5EhKJAaA==
        -----END OPENSSH PRIVATE KEY-----
        EOK
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /decryption is not \(yet\) supported/)
      end

      it "calls a block if provided" do
        block_called = false

        OpenSSL::PKey.from_ssh_key(ssh_key) { block_called = true } rescue nil

        expect(block_called).to be(true)
      end
    end

    context "given a private key that isn't valid base64" do
      let(:ssh_key) { "-----BEGIN OPENSSH PRIVATE KEY-----\nnotbase64!!!\n-----END OPENSSH PRIVATE KEY-----" }

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end

    def private_ssh_key(raw_content)
      "-----BEGIN OPENSSH PRIVATE KEY-----\n#{[raw_content].pack("m")}-----END OPENSSH PRIVATE KEY-----"
    end

    context "given a private key with bad magic" do
      let(:ssh_key) { private_ssh_key("BAD MAGIC HERE!!!!") }

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /incorrect magic found/)
      end
    end

    context "given a private key with no keys" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4none" +
          "\0\0\0\0" +
          "\0\0\0\0"
        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /no keys/)
      end
    end

    context "given a private key with multiple keys" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4none" +
          "\0\0\0\0" +
          "\0\0\0*"
        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /multiple keys/)
      end
    end

    context "given a private key with different check values" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4none" +
          "\0\0\0\0" +
          "\0\0\0\x01" +
          "\0\0\0\0" +
          "\0\0\0\x08" +
          "abcd" +
          "1234"
        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /check values don't match/)
      end
    end

    context "given a private key with a mystery KDF" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4ohai" +
          "\0\0\0\0" +
          "\0\0\0\x01" +
          "\0\0\0\0" +
          "\0\0\0\x08" +
          "abcd" +
          "1234"
        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /KDF "ohai"/)
      end
    end

    context "given a private key with a mystery key type" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4none" +
          "\0\0\0\0" +
          "\0\0\0\x01" +
          "\0\0\0\0" +
          "\0\0\0\x15" +
          "abcd" +
          "abcd" +
          "\0\0\0\x09ssh-ohai!"

        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /Unknown key type ssh-ohai!/)
      end
    end

    context "given an ECDSA private key with a mystery curve" do
      let(:ssh_key) do
        private_ssh_key(
          "openssh-key-v1\0" +
          "\0\0\0\4none" +
          "\0\0\0\4none" +
          "\0\0\0\0" +
          "\0\0\0\x01" +
          "\0\0\0\0" +
          "\0\0\0\x26" +
          "abcd" +
          "abcd" +
          "\0\0\0\x0eecdsa-sha2-foo" +
          "\0\0\0\x08nistohai"

        )
      end

      it "raises an exception" do
        expect { pkey }.to raise_error(OpenSSL::PKey::PKeyError, /Unknown curve identifier nistohai/)
      end
    end
  end
end
