package Digest;

use strict;
use vars qw($VERSION %MMAP $AUTOLOAD);

$VERSION = "0.01";

%MMAP = (
  "SHA-1"      => "Digest::SHA1",
  "HMAC-MD5"   => "Digest::HMAC_MD5",
  "HMAC-SHA-1" => "Digest::HMAC_SHA1",
);

sub new
{
    shift;  # class ignored
    my $algorithm = shift;
    my $class = $MMAP{$algorithm} || "Digest::$algorithm";
    no strict 'refs';
    unless (%{"$class\::"}) {
	eval "require $class";
	die $@ if $@;
    }
    $class->new(@_);
}

sub AUTOLOAD
{
    my $class = shift;
    my $algorithm = substr($AUTOLOAD, rindex($AUTOLOAD, '::')+2);
    $class->new($algorithm, @_);
}

1;

__END__
