require 'tempfile'

class PemObject
  attr_reader :pem_text

  def initialize(pem_text, temp_name)
    @pem_text = pem_text
    @pem_file = Tempfile.new("#{temp_name}.pem")
    @pem_file.write(pem_text)
    @pem_file.close
  end

  def pem_path
    @pem_file.path
  end
end

class Certificate < PemObject
  def initialize(x509_text, pem_text, index = 0)
    super(pem_text, "cert-#{index}")
    @x509_text = x509_text
    extract_parties
  end

  def extract_parties
    @x509_text.split("\n").each do |line|
      if line =~ /Subject: (?<subject>.*$)/
        @subject = $~[:subject]
      elsif line =~ /Issuer: (?<issuer>.*$)/
        @issuer = $~[:issuer]
      end
    end

    @self_signed =  @subject == @issuer
  end
end

class PrivateKey < PemObject
  def initialize(pem_text)
    super(pem_text, "prviate-key")
  end

  def self.from_file(input)
    pem_text = input.readlines.join('')
    if OpenSSL.check_key(pem_text)
      PrivateKey.new(pem_text)
    end
  end
end


# This module is a wrapper around the command line OpenSSL program, as
# opposed to using Ruby binings to the OpenSSL library.  This was done for
# two reasons: it's comparatively easy to implement, and by running
# everything in an external process, we get a layer of protection (i.e., a
# separate address space) from crazy stuff coming in from the internet.  The
# downsides include overhead (separate process, resources, etc.) and
# potential brittleness that comes from parsing text output from the command.
module OpenSSL
  # parse PEM text into the x509 dump from OpenSSL
  def self.parse_cert(pem_text)
    # throwing away error messages from openssl
    result = `echo '#{pem_text}' | openssl x509 -noout -text 2> /dev/null`
    unless $?.success?
      raise ArgumentError.new("Failed to parse delimited PEM certificate")
    end

    result
  end

  def self.check_key(pem_text)
    # discard all output - just look for the status
    `echo '#{pem_text}' | openssl pkey -noout -text > /dev/null 2>&1`
    unless $?.success?
      raise ArgumentError.new("Unable to parse private key")
    end

    true
  end

  def self.verify_chain(certs)
    # NB: this doesn't work on  MacOS (OpenSSL 0.9.8zh 14 Jan 2016), but it
    # does work on Ubunutu with OpenSSL 1.0.1f 6 Jan 2014
    # the certs are assumed to go from leaf to root
    #  -purpose sslserver -untrusted
    leaf_path = certs[0].pem_path

    if certs.size > 1
      # intermediate certs have to be order with root first (not last)
      intermediate_paths = certs[1..-1].reverse.map(&:pem_path)
      args = "-untrusted #{intermediate_paths.join(' -untrusted ')} #{leaf_path}"
    else
      args = leaf_path
    end

    results = `openssl verify -purpose sslserver #{args}`

    parse_verify_results(results)
  end

  def self.parse_verify_results(results)
    status = false
    error_msg = nil

    lines = results.split("\n")
    # only looking at first line of output for 'OK'.  It is possible to get
    # 'OK' after error messages - we consider that an error, not OK.
    if lines.first =~ /OK$/
      status = true
    else
      # first line is the subject, second is the message
      # cert4.pem: /C=US/O=The Go Daddy Group...
      subject = lines[0].split(':')[1]
      # error 20 at 0 depth lookup:unable to get local issuer certificate
      msg = lines[1].split(':')[1]
      error_msg = "Error '#{msg}' with certificated for '#{subject}'"
    end

    [status, error_msg]
  end

  def self.verify_key_and_cert(priv_key, cert)
    key_sum = `openssl pkey -in #{priv_key.pem_path} -pubout -outform pem | sha256sum`
    cert_sum = `openssl x509 -in #{cert.pem_path} -pubkey -noout -outform pem | sha256sum`

    key_sum == cert_sum
  end
end

class CertBundle
    def initialize(certs)
      @certficates = certs
    end

    def size
      @certficates.size
    end

    def [](idx)
      @certficates[idx]
    end

    def verify
      OpenSSL.verify_chain(@certficates)
    end

    # raises ArgumentError for serious errors like PEM formatting, wrong
    # object type, etc.
    def self.parse_bundle_file(in_file)
      certs = []
      cert_num = 1
      pem_text = ""
      in_file.each do |line|
        pem_text += line
        if (line =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/)
            parsed_cert = OpenSSL.parse_cert(pem_text)
            certs << Certificate.new(parsed_cert, pem_text, cert_num)
            pem_text = ""
            cert_num += 1
        end
      end

      if !pem_text.empty?
        raise ArgumentError.new("Failed to find end of certificate")
      end

      CertBundle.new(certs)
    end
end


def read_bundle
  certs = CertBundle.parse_bundle_file(ARGF)
  puts "Found #{certs.size} certificates in chain"
  status, message = certs.verify

  if status
    puts "Certificate chain OK"
  else
    puts "Error found in chain:"
    puts message
  end
end

def check_key
  priv_name = ARGV.shift
  cert_name = ARGV.shift

  priv_key = PrivateKey.from_file(File.open(priv_name, 'r'))
  cert = CertBundle.parse_bundle_file(File.open(cert_name, 'r'))[0]
  if OpenSSL.verify_key_and_cert(priv_key, cert)
    puts "The key matches the certficate"
  else
    puts "The key and certificate do not match"
  end
end

if __FILE__ == $0
  if ARGV.size == 1
    read_bundle
  elsif ARGV.size == 2
    check_key
  else
    puts "Usage: cert_bundle.rb cert-bundle.pem  - verify a certficiate bundle"
    puts "       cert_bundle.rb priv-key.pem cert-bundle.pem  - check a key against a certificate/bundle"
  end
end
