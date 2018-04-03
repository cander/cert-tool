
require_relative '../cert_bundle.rb'

describe 'CertBundle' do
  def parse_file(name)
    CertBundle.parse_bundle_file(File.open(name, "r"))
  end

  describe 'parse_bundle_file' do
    it 'read a single valid cert OK' do
      certs = parse_file("data/certs/leaf-cert.pem")

      expect(certs.size).to eq(1)
    end

    it 'read two valid certs OK' do
      certs = parse_file("data/certs/two-gd-certs.pem")

      expect(certs.size).to eq(2)
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

  describe 'verify' do
    it 'should verify a root certificate' do
      certs = parse_file("data/certs/root-cert.pem")
      status, error_msg = certs.verify

      expect(status).to be true
      expect(error_msg).to be_nil
    end

    it 'should reject a leaf w/o its chain' do
      certs = parse_file("data/certs/leaf-cert.pem")
      status, error_msg = certs.verify

      expect(status).to be false
      expect(error_msg).to match(/unable to get local issuer certificate/)
    end

    it 'should reject an expired cert in the chain' do
      certs = parse_file("data/certs/expired-chain.pem")
      status, error_msg = certs.verify

      expect(status).to be false
      expect(error_msg).to match(/certificate has expired/)
    end

    it 'should reject a cert with the wrong purpose' do
      certs = parse_file("data/certs/two-gd-certs.pem")
      status, error_msg = certs.verify

      expect(status).to be false
      expect(error_msg).to match(/unsupported certificate purpose/)
    end

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
