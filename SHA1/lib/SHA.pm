package SHA;

use strict;
use vars qw($VERSION @ISA @EXPORT_OK);

$VERSION = '2.00'; # $Date$

require Digest::SHA1;
@ISA=qw(Digest::SHA1);

require Exporter;
*import = *Exporter::imprt;
@EXPORT_OK=qw(sha_version);

sub hexdigest
{
    my $self = shift;
    join(" ", unpack("A8 A8 A8 A8 A8", $self->SUPER::hexdigest(@_)));
}

sub hash        { shift->new->add(@_)->digest;    }
sub hexhash     { shift->new->add(@_)->hexdigest; }
sub sha_version { "SHA-1"; }

1;
