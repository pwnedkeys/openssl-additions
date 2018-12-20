This is a collection of miscellaneous quality-of-life helpers to Ruby's core
OpenSSL module.  They're intended to make working with OpenSSL a little less
frustrating.


# Installation

Due to recent changes in the `openssl` standard library, this gem requires
Ruby 2.5 or later with the `openssl` extension.  Assuming you've got that
available, you can install as a gem:

    gem install openssl-additions

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

All classes are fully documented with YARD comments, so [the
online docs](https://rubydoc.info/gems/openssl-additions) are actually useful.
A brief summary of features, though, appears below.


## Consistent SPKIs

Not all OpenSSL key types provide a consistent `SubjectPublicKeyInfo` data
structure to work with, so I added one, along with helpers on the existing
SPKI-related classes to extract one.

    require "openssl/x509/spki"
	
	key = OpenSSL::PKey::EC.new("prime256v1").generate_key
	spki = key.to_spki
	spki.to_der   # => bundle of gibberish
	spki.spki_fingerprint.hexdigest  # => lots of hex characters

	cert = OpenSSL::X509::Certificate.new(File.read("/tmp/cert.pem"))
	spki = cert.to_spki
    # ... and so on

## Parsing SSH public keys into PKeys

Ever needed an SSH public key in an OpenSSL-compatible object?  Neither did I
until recently, but once I did, I wrote this.

    require "openssl/pkey"

	key = OpenSSL::PKey.from_ssh_key(File.read("~/.ssh/id_rsa.pub"))
	key.class     # => OpenSSL::PKey::RSA
	key.public?   # => true
	key.private?  # => false


# Contributing

See `CONTRIBUTING.md`.


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2018  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

	In addition, as a special exception, the copyright holders give permission
	to link the code of portions of this program with the OpenSSL library. You
	must obey the GNU General Public License in all respects for all of the
	code used other than OpenSSL. If you modify file(s) with this exception,
	you may extend this exception to your version of the file(s), but you are
	not obligated to do so. If you do not wish to do so, delete this exception
	statement from your version. If you delete this exception statement from
	all source files in the program, then also delete it here.
