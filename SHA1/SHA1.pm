package Digest::SHA1;

use strict;
use vars qw($VERSION @ISA @EXPORT_OK);

$VERSION = '1.00';  # $Date$

require Exporter;
*import = \&Exporter::import;
@EXPORT_OK = qw(sha1 sha1_hex sha1_base64);

require DynaLoader;
@ISA=qw(DynaLoader);
Digest::SHA1->bootstrap($VERSION);

*reset = \&new;

1;
__END__

=head1 NAME

Digest::SHA1 - Perl interface to the SHA1 Algorithm

=head1 SYNOPSIS

 # Functional style
 use Digest::SHA1  qw(sha1 sha1_hex sha1_base64);

 $digest = sha1($data);
 $digest = sha1_hex($data);
 $digest = sha1_base64($data);
    

 # OO style
 use Digest::SHA1;

 $ctx = Digest::SHA1->new;

 $ctx->add($data);
 $ctx->addfile(*FILE);

 $digest = $ctx->digest;
 $digest = $ctx->hexdigest;
 $digest = $ctx->b64digest;

=head1 DESCRIPTION

XXX The C<Digest::SHA1> module allows you to use the RSA Data Security
XXX Inc. SHA1 Message Digest algorithm from within Perl programs.  The
XXX algorithm takes as input a message of arbitrary length and produces as
XXX output a 128-bit "fingerprint" or "message digest" of the input.

The C<Digest::SHA1> programming interface is identical to the interface
of C<Digest::MD5>.

=head1 SEE ALSO

L<Digest>, L<Digest::MD5>

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

 Copyright 1999 Gisle Aas.

=head1 AUTHOR

Gisle Aas <gisle@aas.no>

=cut
