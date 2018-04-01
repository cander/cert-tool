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
    # assume MacOS (OpenSSL 0.9.8zh 14 Jan 2016)  where the command hast to look like:
    # openssl verify -CAfile root.pem -untrusted <(cat intermediate.pems ) leaf.pem 
    # because it won't take multiple -untrusted flags
    # and, assume we have at least 3 certs
    num_certs = certs.size
    root_pem = certs[-1].pem_path
    leaf_pem = certs[0].pem_path
    results = `openssl verify #{leaf_pem}`

    parse_verify_results(results)
  end

  def self.parse_verify_results(results)
    status = false
    error_msg = nil

    lines = results.split("\n")
    # only looking at last line of output ignores 'warnings' before 'OK'
    if lines[-1] =~ /OK$/
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

    def pem_text(idx)
      @certficates[idx].pem_text
    end

    def verify
      puts "Verify chain of #{@certficates.size} certs..."
      OpenSSL.verify_chain(@certficates)
    end

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


if __FILE__ == $0
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
