class Certificate
    def initialize(x509_text, pem_text)
        @x509_text = x509_text
        @pem_text = pem_text
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

end

class CertBundle
    def initialize(certs)
      @certficates = certs
    end

    def size
      @certficates.size
    end

    def self.parse_bundle_file(in_file)
      certs = []
      pem_text = ""
      in_file.each do |line|
        pem_text += line
        if (line =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/)
            parsed_cert = OpenSSL.parse_cert(pem_text)
            certs << Certificate.new(parsed_cert, pem_text)
            pem_text = ""
        end
      end

      if !pem_text.empty?
        raise ArgumentError.new("Failed to find end of certificate")
      end

      CertBundle.new(certs)
    end
end
