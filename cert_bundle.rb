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
            # throwing away error messages from openssl
            parsed_cert = `echo '#{cert_strs}' | openssl x509 -noout -text 2> /dev/null`
            if $?.success?
              result << Certificate.new(parsed_cert)
              cert_strs = ""
            else
              raise ArgumentError.new("Failed to parse delimited certificate")
            end
        end
      end

      if !cert_strs.empty?
        raise ArgumentError.new("Failed to find end of certificate")
      end

      result
    end
end
