use strict;
use IO::Socket::INET;
use Test::More tests => 6;
BEGIN { use_ok('Net::Proxy::Type') };

my $pt = Net::Proxy::Type->new();
ok(defined($pt), "new()");
isa_ok($pt, "Net::Proxy::Type");

my $sock = IO::Socket::INET->new(Listen => 3)
	or die $@;
my ($host, $port) = ($sock->sockhost eq "0.0.0.0" ? "127.0.0.1" : $sock->sockhost, $sock->sockport);
$sock->close();
is($pt->get($host, $port), Net::Proxy::Type::DEAD_PROXY, "DEAD_PROXY test");
my ($type, $conn_time) = $pt->get($host, $port);
is($type, Net::Proxy::Type::DEAD_PROXY, "DEAD_PROXY in list context test");
is($conn_time, 0, "DEAD_PROXY conn time");

