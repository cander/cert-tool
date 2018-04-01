
require_relative '../cert_bundle.rb'

describe 'CertBundle' do
    def parse_file(name)
      CertBundle.parse_bundle_file(File.open(name, "r"))
    end

    it 'read a valid cert OK' do
      certs = parse_file("data/certs/one-good-cert.pem")

      expect(certs.size).to eq(1)
    end

    it 'read a chain of 4 certs OK' do
      certs = parse_file("data/certs/expired-chain.pem")

      expect(certs.size).to eq(4)
    end

    it 'raise an exception about an incomplete cert' do
      expect{ parse_file("data/certs/incomplete-cert.pem") }.to raise_error(ArgumentError)
    end

    it 'raise an exception for a corrupted cert' do
      expect{ parse_file("data/certs/corrupted-cert.pem") }.to raise_error(ArgumentError)
    end
end

describe 'PrivateKey' do
  it 'should read a valid private key' do
    input = File.open("data/keys/self-signed-key.pem")
    key = PrivateKey.from_file(input)

    expect(key).to_not be_nil
  end

  it 'should raise an error for an invalid private key' do
    input = File.open("data/certs/corrupted-cert.pem")

    expect { PrivateKey.from_file(input) }.to raise_error(ArgumentError)
  end
end
