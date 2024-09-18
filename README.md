NAME
====

Crypt::RC4 - Raku implementation of the legacy RC4 encryption algorithm

SYNOPSIS
========

```raku
# Functional Style
  use Crypt::RC4;
  my $encrypted = RC4( $passphrase, $plaintext );
  my $decrypt = RC4( $passphrase, $encrypted );

# OO Style
  use Crypt::RC4;
  my Crypt::RC4 $ref .= new: :key($passphrase);
  my $encrypted = $ref.RC4( $plaintext );

  my Crypt::RC4 $ref2 .= new: :key($passphrase);
  my $decrypted = $ref2.RC4( $encrypted );
```

DESCRIPTION
===========

A simple implementation of the RC4 algorithm, developed by RSA Security, Inc.

RC4 is no longer recommended for encryption. This module is provided for demonstration purposes and backwards compatibility only. 

AUTHOR
======

Kurt Kincaid (sifukurt@yahoo.com) Ronald Rivest for RSA Security, Inc.

BUGS
====

The RC4 algorithm is considered weak and insecure for modern cryptographic applications. It is susceptible to significant vulnerabilities, making it unsuitable for ensuring data confidentiality. Several attacks, such as the Fluhrer-Mantin-Shamir attack and biases in the keystream, have been discovered over the years. Due to these vulnerabilities, the RC4 algorithm is no longer considered secure.

Furthermore, this implementation is limited to 256 bit encryption keys.

LICENSE
=======

This is free software and may be modified and/or redistributed under the same terms as Perl itself.

SEE ALSO
========

[perl](perl), [http://www.cypherspace.org](http://www.cypherspace.org), [http://www.rsasecurity.com](http://www.rsasecurity.com), [http://www.achtung.com/crypto/rc4.html](http://www.achtung.com/crypto/rc4.html), [http://www.columbia.edu/~ariel/ssleay/rrc4.html](http://www.columbia.edu/~ariel/ssleay/rrc4.html)

cut
===



