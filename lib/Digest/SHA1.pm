package Digest::SHA1;

# This demonstrates what need to be done to conform to the same
# interface as Digest::MD5 (and Digest::HMAC).  This should really be
# implemented similar to how Digest::MD5 is, and SHA made into a stub.

$VERSION = '0.01';

use SHA 1.2;

my $sha_ver = SHA::sha_version();
die "Wrong SHA version ($sha_ver)" unless $sha_ver eq "SHA-1";

sub new {
    my $class = shift;
    my $self = SHA->new;
    bless \$self, $class;
}

sub reset
{
    my $self = shift;
    $$self->reset(@_);
    $self;
}

sub add
{
    my $self = shift;
    $$self->add(@_);
    $self;
}

sub addfile
{
    my $self = shift;
    $$self->addfile(@_);
    $self;
}

sub digest
{
    my $self = shift;
    $$self->digest(@_);
}

sub hexdigest
{
    unpack("H*", shift->digest);
}

sub b64digest
{
    require MIME::Base64;
    my $digest = MIME::Base64::encode(shift->digest, '');
    $digest =~ s/=+$//;
    $digest;
}

# Functional interface
require Exporter;
*import = \&Exporter::import;
@EXPORT_OK = qw(sha1 sha1_hex sha1_base64);

sub sha1          {  Digest::SHA1->new->add(@_)->digest;    }
sub sha1_hex      {  Digest::SHA1->new->add(@_)->hexdigest; }
sub sha1_base64   {  Digest::SHA1->new->add(@_)->b64digest; }

1;
