require_relative '../cert_bundle.rb'

describe 'OpenSSL' do
  describe 'parse_verify_results' do
    it 'should recognize a OK status' do
      status, msg = OpenSSL.parse_verify_results("good4.pem: OK\n")

      expect(status).to be true
      expect(msg).to be_nil
    end

    it 'should report an OK status with an error message as an error' do
      status, msg = OpenSSL.parse_verify_results("cert4.pem: /C=US/O=The Go Daddy Group, Inc./OU=Go Daddy Class 2 Certification Authority
      error 18 at 0 depth lookup:self signed certificate
      OK")

      expect(status).to be false
      expect(msg).to_not be_nil
    end

    it 'should report an error with a message' do
      status, msg = OpenSSL.parse_verify_results("cert3.pem: /C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./CN=Go Daddy Root Certificate Authority - G2
      error 20 at 0 depth lookup:unable to get local issuer certificate")

      expect(status).to be false
      expect(msg).to match(/unable to get local issuer certificate/)
      expect(msg).to match(%r|/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com|)
    end
  end

  describe 'verify_key_and_cert' do
    it 'should report a matching pair as OK' do
      priv_key = PrivateKey.from_file(File.open("data/keys/self-signed-key.pem", 'r'))
      cert = CertBundle.parse_bundle_file(File.open("data/certs/self-signed-cert.pem", 'r'))[0]

      expect(OpenSSL.verify_key_and_cert(priv_key, cert)).to be true
    end

    it 'should report a mismatched pair as not OK' do
      priv_key = PrivateKey.from_file(File.open("data/keys/random-key.pem", 'r'))
      cert = CertBundle.parse_bundle_file(File.open("data/certs/self-signed-cert.pem", 'r'))[0]

      expect(OpenSSL.verify_key_and_cert(priv_key, cert)).to be false
    end
  end
end
