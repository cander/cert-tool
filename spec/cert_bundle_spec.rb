
require_relative '../cert_bundle.rb'

describe 'CertBundle' do
    it 'read a valid cert OK' do
      CertBundle.parse_bundle_file(File.open("data/certs/one-good-cert.pem", "r"))
    end
end
