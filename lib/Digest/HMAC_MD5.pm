package Digest::HMAC_MD5;

use strict;
use Digest::MD5  qw(md5);
use Digest::HMAC qw(hmac);

# OO interface
use vars qw(@ISA);
@ISA=qw(Digest::HMAC);
sub new
{
    my $class = shift;
    $class->SUPER::new($_[0], "Digest::MD5", 64);
}

# Functional interface
require Exporter;
*import = \&Exporter::import;
use vars qw(@EXPORT_OK);
@EXPORT_OK=qw(hmac_md5 hmac_md5_hex);

sub hmac_md5
{
    hmac($_[0], $_[1], \&md5, 64);
}

sub hmac_md5_hex
{
    unpack("H*", &hmac_md5)
}

1;
