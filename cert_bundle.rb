class Certificate
    def initialize(x509_text)
        @x509_text = x509_text
    end
end

class CertBundle
    def self.parse_bundle_file(in_file)
      result = []
      cert_strs = ""
      in_file.each do |line|
        cert_strs += line
        if (line =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/)
            puts "Found a cert"
            parsed_cert = `echo '#{cert_strs}' | openssl x509 -noout -text`
            if $?.success?
              puts "parsed the cert"
              result << Certificate.new(parsed_cert)
              cert_strs = ""
            else
              puts "failed to parse"
            end
        end
      end

      if !cert_strs.empty?
        raise ArgumentError.new("Failed to find end of certificate")
      end

      result
    end
end

if __FILE__ == $0
    CertBundle.parse_bundle_file(ARGF)
end
