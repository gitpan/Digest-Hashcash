=head1 NAME

Digest::Hashcash - generate Hashcash stamps (http://www.hashcash.org)

=head1 SYNOPSIS

 use Digest::Hashcash;

=head1 DESCRIPTION

This module implements the hashcash hash (or digest, although it's
not clearly a digest). For all your information needs please visit
http://www.hashcash.org.

One thing to note about this module is that it requires ISO C99
support, both in your compiler and your standard library.  If you
don't have a compiler that supports ISO C, get gcc at
http://gcc.gnu.org/ :)

=over 4

=cut

package Digest::Hashcash;

use Time::Local;
use Time::HiRes;

require XSLoader;

no warnings;

$VERSION = 0.04;

XSLoader::load Digest::Hashcash, $VERSION;

=item $secs = estimate_time $size

Estimate the average time necessary to calculate a token of the given
size.

See also C<estimate_size>.

=item $size = estimate_size $time[, $min]

Estimate the size that can be calculated in the given time (which is an
upper bound). The function will not return a size less then C<min>.

Estimating the time to be used can go wrong by as much as 50% (but is
usually quite accurate), and the estimation itself can take as much as a
second on slower (<pentium) machines, but faster machines (1Ghz P3 for
example) usually handle it within a hundredth of a second or so.

The estimation will be done only once, so you can call this fucntion as
often as you like without incuring the overhead everytime.

=cut

my $rounds;

sub _rounds {
   $rounds ||= &_estimate_rounds();
}

sub estimate_time {
   my ($size) = @_;
   2**$size / &_rounds;
}

sub estimate_size {
   my ($time, $min) = @_;
   $time = (log $time * $rounds) / log 2;
   $time < $min ? $min : int $time;
}

=item $cipher = new Digest::Hashcash [param => value...]

=over 4

=item size => 20

The number of collisions, in bits. Every bit increases the time to create
the token (and thus the cash) by two.

=item vers => 1

Default version 1.  Can produce version 0 if required for backwards
compatibility.

=item uid => ""

A string used to make the token more unique (e.g. the senders address)
and reduce token collisions. The string must only contain characters
valid for the trial part of the token, e.g. uuencoded, base64 or
e-mail-address-parts are useful here.  Deprecated: use extension field
if required.

=item extrarand => 0

The extra bytes of randomness to add to the token in addition to the
standard amount. Each byte adds a little bit over 6 bit of randomness to
the token.

The standard amount of randomness is 8 (> 51 bits of randomness).

=item timestamp => 0

The timestamp to use. A value of 0 (the default) means to use the current
time.

=back

=item $token = $cipher->hash ($data [, param => value...])

Creates and returns a new token. This can take some time.

Any additional parameters are interpreted the same way as arguments to
C<new>.

=item $prefix = $cipher->verify ($token)

Version 0: Checks the given token and returns the number of collision
bits.

Version 1: Returns 0 if stated value is more than the computed
collision value, otherwise returns the stated stamp value.

Any additional parameters are interpreted the same way as arguments to
C<new>.

=item $version = $cipher->version ($token)

Returns the version of the stamp (currently 0 or 1).

=item $resource = $cipher->resource ($token)

Returns the resource part, or C<undef>.

=item $tstamp = $cipher->timestamp ($token)

Returns the timestamp part (in the same format as perls C<time>), or
C<undef>.

=item $extension = $cipher->extension ($token [,$name [,$var]])

For Version 1 stamps returns the extension part; for Version 0 stamps
returns undef.  In a scalar context returns the extension string, in
array context returns associative array containing extensions as keys
and their values as the corresponding value.  If the optional name
argument is given, returns info but about that extension (ie decodes
the options of that extension if called in array context); finally if
the optional var argument also is given reports just the (scalar)
value of that variable in the named extension.

Note it is valid for an extension to exist (the key exists in the
associative array) but to have undefined value, this corresponds to a
boolean option without a value.  Like "noreply;foo=bar" has two
extensions, noreply and foo; noreply has no associated value, so the
method extension would parse such a stamp into an associative array
containing key "noreply" with an undefined value; and key "foo"
containing associated value "bar".

=back

=cut

sub encode {
    my %ext = shift;
    my $res;
    foreach $key (keys %ext) {
	if ( index( $ext[$key], "," ) >= 0 ) {
	    $ext[$key] = split( ",", $ext[$key] );
	}
    }
}

sub new {
   my $class = shift;

   bless { @_ }, $class;
}

sub hash {
   my $self = shift;
   my $resource = shift;
   my %arg = ( vers => 1, %$self, resource => $resource, @_ );

   &_gentoken(@arg{qw(size vers timestamp resource extension uid extrarand)});
}

sub verify {
   my ($self, $token) = (shift, shift);

   my $prefix = &_prefixlen($token);

   if ($token =~ /^0:/) {
      return $prefix >= 0 ? $prefix : 0;
   } elsif ($token =~ /^1:/) {
      ($ver, $bits, $ts, $res, $ext, $junk, $count) = split(':', $token, 7);
      return $prefix >= $bits ? $bits : 0;
   }
   else { return undef; }
}

sub resource {
   my ($self, $token) = @_;

   if ($token =~ /^0:/) {
      ($ver, $ts, $res, $rand) = split(':', $token, 4);
   }
   elsif ($token =~ /^1:/) {
      ($ver, $bits, $ts, $res, $ext, $junk, $count) = split(':', $token, 7);
   }
   else { return undef; }
   return $res;
}

sub timestamp {
   my ($self, $token) = @_;

   if ($token =~ /^0:/) {
      ($ver, $ts, $res, $rand) = split(':', $token, 4);
   }
   elsif ($token =~ /^1:/) {
      ($ver, $bits, $ts, $res, $ext, $junk, $count) = split(':', $token, 7);
   }
   else { return undef; }

   my ($y, $m, $d, $H, $M, $S);
   local $_ = $ts;
   $y = /\G(\d\d)/gc ? $1 : return undef;
   $m = /\G(\d\d)/gc ? $1 : 1;
   $d = /\G(\d\d)/gc ? $1 : 1;
   $H = /\G(\d\d)/gc ? $1 : 0;
   $M = /\G(\d\d)/gc ? $1 : 0;
   $S = /\G(\d\d)/gc ? $1 : 0;

   return timegm $S, $M, $H, $d, $m - 1, $y;
}

sub extension { 
   my ($self, $token, $name, $var) = @_;
   my $bits, $ts, $res, $ext, $junk, $count, @ext, %ext;

   if ($token =~ /^0:/) {
      return undef;
   }
   elsif ($token =~ /^1:/) {
       if ( wantarray ) { %ext = (); }
      ($ver, $bits, $ts, $res, $ext, $junk, $count) = split(':', $token, 7);
      if ( wantarray || defined( $name ) ) {
	  foreach $pair ( split( ";", $ext ) ) {
	      ($nam,$val) = split( "=", $pair, 2 );
	      if ( defined( $name ) ) {
		  if ( $name eq $nam ) {
		      if ( wantarray || defined( $var ) ) {
			  foreach $vpair ( split( ",", $val ) ) {
			      ($vnam,$vval) = split( "=", $vpair, 2 );
			      if ( defined( $var ) ) {
				  if ( $vnam eq $var ) { return $vval; }
			      } else {
				  $ext{$vnam} = $vval;
			      }
			  }
			  return %ext;
		      } else {
			  return $val;
		      }
		  }
	      } else {
		  $ext{$nam} = $val;
	      }
	  }
	  return %ext;
      } else {
	  return $ext;
      }
   }
   else { return undef; }
}

sub version {
   my ($self, $token) = @_;

   if ($token =~ /^0:/) {
      return 0;
   } elsif ($token =~ /^1:/) {
      return 1;
   }
   else { return undef; }
}
=head1 SEE ALSO

L<http://www.hashcash.org>.

=head1 BUGS

 * There is a y2k+100 problem, as I always assume the same as
   Time::Local.  This is a problem with the hashcash specification,
   which specifies years as 2 digits :( Though it hardly matters --
   after 100 years of Moore's law a 20 bit stamp will be tiny and not
   worth storing.

 * extension method could be more efficient (it does not cache its
   parsed results so if used in a loop reparses on each call)

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de

 Adam Back <adam@cypherspace.org> added version 1 support
 http://www.cypherspace.org/adam/

=cut

1;
