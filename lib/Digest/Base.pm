package Digest::Base;

# These must always be implemented by subclasses...
sub new;
sub add;
sub digest;

sub reset { shift->new(@_) }  # depreciated

sub addfile
{
    my($self, $file) = @_;
    my $buf;
    while (read($file, $buf, 1024)) {
	$self->add($buf);
    }
    $self;
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

1;
