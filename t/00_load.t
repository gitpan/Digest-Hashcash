BEGIN { $| = 1; print "1..7\n"; }
END {print "not ok 1\n" unless $loaded;}
use Digest::Hashcash;
$loaded = 1;
print "ok 1\n";

my $c = new Digest::Hashcash
   size => 16,
   uid => "pcg\@goof.com";

my $token = $c->hash ("proprietary\@is.evil");

print $token =~ /pcg\@goof.com/ ? "ok 2\n" : "not ok 2\n";
print $token =~ /proprietary\@is.evil/ ? "ok 3\n" : "not ok 3\n";
print $c->verify ($token) ? "ok 4\n" : "not ok 4\n";

print $c->resource ($token) eq "proprietary\@is.evil" ? "ok 5\n" : "not ok 5\n";

my $t = $c->timestamp ($token);

print $t <= time ? "ok 6\n" : "not ok 6\n";
print $t > time - 3600 ? "ok 7\n" : "not ok 7\n";


