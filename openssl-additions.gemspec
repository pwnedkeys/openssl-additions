begin
  require 'git-version-bump'
rescue LoadError
  nil
end

Gem::Specification.new do |s|
  s.name = "openssl-additions"

  s.version = GVB.version rescue "0.0.0.1.NOGVB"
  s.date    = GVB.date    rescue Time.now.strftime("%Y-%m-%d")

  s.platform = Gem::Platform::RUBY

  s.summary  = "Quality-of-life improvements to the core openssl ruby library"
  s.description = <<~EOF
    This gem provides a consistent, key-type-independent SPKI (SubjectPublicKeyInfo) class,
    a way to generate an SPKI object from a key regardless of type, SSH public key to
    OpenSSL key conversion, and more.
  EOF

  s.authors  = ["Matt Palmer"]
  s.email    = ["matt@hezmatt.org"]
  s.homepage = "https://github.com/pwnedkeys/openssl-additions"

  s.files = `git ls-files -z`.split("\0").reject { |f| f =~ /^(\.|G|spec|Rakefile)/ }

  s.required_ruby_version = ">= 2.5.0"

  s.add_development_dependency 'bundler'
  s.add_development_dependency 'github-release'
  s.add_development_dependency 'git-version-bump'
  s.add_development_dependency 'guard-rspec'
  s.add_development_dependency 'rack-test'
  s.add_development_dependency 'rake', "~> 12.0"
  s.add_development_dependency 'redcarpet'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'yard'
end
