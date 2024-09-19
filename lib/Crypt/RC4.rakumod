#--------------------------------------------------------------------#
# Crypt::RC4
#       Date Written:   07-Jun-2000 04:15:55 PM
#       Last Modified:  13-Dec-2001 03:33:49 PM
#       Author:         Kurt Kincaid (sifukurt@yahoo.com)
#       Copyright (c) 2001, Kurt Kincaid
#           All Rights Reserved.
#       Raku Port:      08-Nov-2015 05:24:25 PM by
#                       david.warring@gmail.com
#
#       This is free software and may be modified and/or
#       redistributed under the same terms as Perl itself.
#--------------------------------------------------------------------#

unit class Crypt::RC4:ver<0.0.6>;

has uint8 @!state;
has uint8 $!x = 0;
has uint8 $!y = 0;

submethod TWEAK(Blob() :$key!) {
    @!state := setup( $key );
}

multi method RC4(@buf is copy --> Array) {
    for @buf {
        my $sx := @!state[++$!x];
        $!y += $sx;
        my $sy := $!y < 0 ?? @!state[*+$!y] !! @!state[$!y];
        ($sx, $sy) = ($sy, $sx);
        my uint8 $mod-sum = $sx + $sy;
        $_ +^= @!state[$mod-sum];
    }
    @buf;
}

multi method RC4(Blob $message --> Blob) {
    my uint8 @buf = $message.list;
    Blob.new: self.RC4( @buf );
}

sub setup( $key --> array[uint8] ) {
    my uint8 @state = 0..255;
    my uint8 $y = 0;
    for 0..255 -> uint8 $x {
        $y += $key[$x % +$key] + @state[$x];
        (@state[$x], @state[$y]) = (@state[$y], @state[$x]);
    }
    @state;
}

our sub RC4($key, |c) is export(:DEFAULT) {
    $?CLASS.new( :$key ).RC4( |c );
}

=begin pod

=head1 NAME

Crypt::RC4 - Raku implementation of the legacy RC4 encryption algorithm

=head1 SYNOPSIS

=begin code :lang<raku>
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
=end code

=head1 DESCRIPTION

A simple implementation of the RC4 algorithm, developed by RSA Security, Inc.

RC4 is no longer recommended for encryption. This module is provided for demonstration
purposes and backwards compatibility only.                                                                         

=head1 AUTHOR

Kurt Kincaid (sifukurt@yahoo.com)
Ronald Rivest for RSA Security, Inc.

David Warring (david.warring@gmail.com)
Perl to Raku port.

=head1 BUGS

The RC4 algorithm is considered weak and insecure for modern cryptographic applications. It is susceptible to significant vulnerabilities, making it unsuitable for ensuring data confidentiality. Several attacks, such as the Fluhrer-Mantin-Shamir attack and biases in the keystream, have been discovered over the years. Due to these vulnerabilities, the RC4 algorithm is no longer considered secure.

Furthermore, this implementation is limited to 256 bit encryption keys.

=head1 LICENSE

This is free software and may be modified and/or
redistributed under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<http://www.cypherspace.org>, L<http://www.rsasecurity.com>,
L<http://www.achtung.com/crypto/rc4.html>,
L<http://www.columbia.edu/~ariel/ssleay/rrc4.html>

=cut

=end pod
