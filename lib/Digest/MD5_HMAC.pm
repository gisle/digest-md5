package Digest::MD5_HMAC;

require Digest::MD5;
require Digest::HMAC;
@ISA=qw(Digest::HMAC);

sub new
{
    my $class = shift;
    $class->SUPER::new($_[0], "Digest::MD5", 64);
}

1;
