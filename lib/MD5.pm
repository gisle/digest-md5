package MD5;  # legacy

use strict;
use vars qw($VERSION @ISA @EXPORT_OK);

$VERSION = '1.9953';  # $Date$

require Digest::MD5;
@ISA=qw(Digest::MD5);

sub hash    { shift->new->add(@_)->digest;    }
sub hexhash { shift->new->add(@_)->hexdigest; }

1;
__END__

=head1 NAME

MD5 - Perl interface to the MD5 Message-Digest Algorithm

=head1 SYNOPSIS

    use MD5;
    
    $context = new MD5;
    $context->reset();
    
    $context->add(LIST);
    $context->addfile(HANDLE);
    
    $digest = $context->digest();
    $string = $context->hexdigest();

    $digest = MD5->hash(SCALAR);
    $string = MD5->hexhash(SCALAR);

=head1 DESCRIPTION

The C<MD5> module is depreciated.  Use C<Digest::MD5> instead.

=head1 SEE ALSO

L<Digest::MD5>

=cut
