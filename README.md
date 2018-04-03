
# Certficate Examination and Testing Tool
This is a collection of code to look at SSL certificates, bundles, and keys,
and report information on them.  This could/should grow into a command line
tool, but right now it's mostly a collection of classes and methods,
including tests for them.  In other words, run the tests to how to use the
functions and what items are tested.

The primary use case is to read a certificate bundle and a private key.  The
following tests are performed:

* the bundle is a collection of PEM encoded certificates
* the certifcates for a chain from the leaf (first in the bundle) to a root
  (last in the bundle).
* the certificates are not expired
* the leaf cerificate is intended for use in an SSL server
* the private key is a PEM enocoded private key
* the private key corresponds to the key for the certificate

## Usage
The code was developed with both Ruby 1.9.3 and 2.0.  The verification code
needs a new-ish version of `openssl`.  In particular, the version the comes
with MacOS 10.12 (`OpenSSL 0.9.8zh 14 Jan 2016`) does not work.  
`OpenSSL 1.0.1f 6 Jan 2014` on Ubuntu worked fine.

### Running Tests
Install the dependencies:
```bundle install --path vendor/bundle```

Run the tests:
```bundle exec rspec spec/ --format=doc```
