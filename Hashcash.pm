=head1 NAME

Digest::Hashcash - generate Hashcashes (http://www.hashcash.org)

=head1 SYNOPSIS

 use Digest::Hashcash;

=head1 DESCRIPTION

This module implements the hashcash hash (or digest, although it's
not clearly a digest). For all your information needs please visit
http://www.hashcash.org.

One thing to note about this module is that it requires ISO C99 support,
both in your compiler and your standard library.  If you don't have a
compiler that supports ISO C, get gcc at http://gcc.gnu.org/ :)

=over 4

=cut

package Digest::Hashcash;

use Time::Local;

require XSLoader;

no warnings;

$VERSION = 0.01;

XSLoader::load Digest::Hashcash, $VERSION;

=item $cipher = new [param => value...]

=over 4

=item size => 20 + some

The number of collisions, in bits. Every bit increases the time to create
the token (and thus the cash) by two.

=item uid => ""

A string used to make the token more unique (e.g. the senders address)
and reduce token collisions. The string must only contain characters
valid for the trial part of the token, e.g. uuencoded, base64 or
e-mail-address-parts are useful here.

=item extrarand => 0

The extra bytes of randomness to add to the token in addition to the
standard amount. Each byte adds a little bit over 6 bit of randomness to
the token.

The standard amount of randomness is 8 (> 51 bits of randomness).

=item timestamp => 0

The timestamp to use. A value of 0 (the default) means to use the current
time.

=back

=item $token = $cipher->hash($data [, param => value...])

Creates and returns a new token. This can take some time.

Any additional parameters are interpreted the same way as arguments to
C<new>.

=item $prefix = $cipher->verify($token [, param => value...]))

Checks the given token and returns true if the token has the minimum
number of prefix bits, or false otherwise.  The value returned is actually
the number of collisions, so to find the number of collisions bits specify
C<< collisions => 0 >>.

Any additional parameters are interpreted the same way as arguments to
C<new>.

=item $resource = $cipher->resource($token)

Returns the resource part, or C<undef>.

=item $tstamp = $ciper->timestamp($token)

Returns the timestamp part (in the same format as perl's C<time>), or
C<undef>.

=back

=cut

sub new {
   my $class = shift;

   bless { @_ }, $class;
}

sub hash {
   my $self = shift;
   my %arg = (%$self, resource => @_);

   &_gentoken(@arg{qw(size timestamp resource uid extrarand)});
}

sub verify {
   my ($self, $token) = (shift, shift);
   my %arg = (%$self, @_);

   my $prefix = &_prefixlen($token);

   $prefix < $arg{size}
      ? undef
      : $prefix;
}

sub resource {
   my ($self, $token) = @_;

   $token =~ /^\d+:\d*:(.*):/
      or return undef;

   return $1;
}

sub timestamp {
   my ($self, $token) = @_;

   $token =~ /^\d+:(\d*):.*:/
      or return undef;

   my ($y, $m, $d, $H, $M, $S);
   local $_ = $1;
   $y = /\G(\d\d)/gc ? $1 : return undef;
   $m = /\G(\d\d)/gc ? $1 : 1;
   $d = /\G(\d\d)/gc ? $1 : 1;
   $H = /\G(\d\d)/gc ? $1 : 0;
   $M = /\G(\d\d)/gc ? $1 : 0;
   $S = /\G(\d\d)/gc ? $1 : 0;

   return timegm $S, $M, $H, $d, $m - 1, $y;
}

=head1 SEE ALSO

L<http://www.hashcash.org>.

=head1 BUGS

 * There is a y2k+100 problem, as I always assume the same as Time::Local.
   This is a problem with the hashcash specification, which specifies
   yeras as 2 digits :(

=head1 AUTHOR

 Marc Lehmann <pcg@goof.com>
 http://home.schmorp.de

=cut

1;

