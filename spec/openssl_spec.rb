

require_relative '../cert_bundle.rb'

describe 'OpenSSL' do
  describe 'parse_verify_results' do
    it 'should recognize a OK status' do
      status, msg = OpenSSL.parse_verify_results("good4.pem: OK\n")

      expect(status).to be true
      expect(msg).to be_nil
    end

    it 'should recognize a OK status with warnings' do
      status, msg = OpenSSL.parse_verify_results("cert4.pem: /C=US/O=The Go Daddy Group, Inc./OU=Go Daddy Class 2 Certification Authority
      error 18 at 0 depth lookup:self signed certificate
      OK")

      expect(status).to be true
      expect(msg).to be_nil
    end

    it 'should report an error with a message' do
      status, msg = OpenSSL.parse_verify_results("cert3.pem: /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./CN=Go Daddy Root Certificate Authority - G2
      error 20 at 0 depth lookup:unable to get local issuer certificate")

      expect(status).to be false
      expect(msg).to match(/unable to get local issuer certificate/)
      expect(msg).to match(%r|/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com|)
    end
  end
end
