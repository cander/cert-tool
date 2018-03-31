require 'tempfile'

class Certificate
    attr_reader :pem_text

    def initialize(x509_text, pem_text, index = 0)
        @x509_text = x509_text
        @pem_text = pem_text
        @pem_file = Tempfile.new("cert-#{index}.pem")
        puts @pem_file.path
        @pem_file.write(pem_text)
        @pem_file.close
    end

    def pem_path
        @pem_file.path
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

  def self.verify_chain(certs)
    # assume MacOS where the command hast to look like:
    # openssl verify -CAfile root.pem -untrusted <(cat intermediate.pems ) leaf.pem 
    # because it won't take multiple -untrusted flags
    # and, assume we have at least 3 certs
    num_certs = certs.size
    root_pem = certs[-1].pem_path
    leaf_pem = certs[0].pem_path
    puts `openssl verify #{leaf_pem}`
    #puts `openssl verify -CAfile <(echo #{root_pem}) <(echo #{leaf.pem })`

  end


end

class CertBundle
    def initialize(certs)
      @certficates = certs
    end

    def size
      @certficates.size
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


if __FILE__ == $0
  certs = CertBundle.parse_bundle_file(ARGF)
  puts "Found #{certs.size} certificates"
  certs.verify

end
