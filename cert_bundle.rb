
class CertBundle
    def self.parse_bundle_file(in_file)
      cert_strs = ""
      in_file.each do |line|
        cert_strs += line
        if (line =~ /^\-+END(\s\w+)?\sCERTIFICATE\-+$/)
            puts "Found a cert"
            puts `echo '#{cert_strs}' | openssl x509 -noout -text`
        end
      end

    end
end

if __FILE__ == $0
    CertBundle.parse_bundle_file(ARGF)
end
