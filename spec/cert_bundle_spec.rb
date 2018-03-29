
require_relative '../cert_bundle.rb'

describe 'CertBundle' do
    def parse_file(name)
      CertBundle.parse_bundle_file(File.open(name, "r"))
    end

    it 'read a valid cert OK' do
      certs = parse_file("data/certs/one-good-cert.pem")

      expect(certs.size).to eq(1)
    end

    it 'raise and exception about an incomplete cert' do
      expect{ parse_file("data/certs/incomplete-cert.pem") }.to raise_error(ArgumentError)
    end
end
