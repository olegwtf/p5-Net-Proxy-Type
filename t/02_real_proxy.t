use strict;
use Test::More;
use Net::Proxy::Type;

unless ($ENV{TEST_PROXY_HOST}) {
	plan skip_all => 'TEST_PROXY_HOST environment variable not set';
}
else {
	plan tests => 10
}

my $pt = Net::Proxy::Type->new(strict => 1);
is($pt->get("$ENV{TEST_PROXY_HOST}:1080"), Net::Proxy::Type::SOCKS4_PROXY, 'get for socks');
is($pt->is_socks4("$ENV{TEST_PROXY_HOST}:1080"), 1, 'is socks4');
is($pt->is_socks5("$ENV{TEST_PROXY_HOST}:1080"), 1, 'is socks5');
is($pt->is_http("$ENV{TEST_PROXY_HOST}:1080"), 0, 'is http for socks');
is($pt->is_https("$ENV{TEST_PROXY_HOST}:1080"), 0, 'is https for socks');
is($pt->get("$ENV{TEST_PROXY_HOST}:3128"), Net::Proxy::Type::CONNECT_PROXY, 'get for http(s)');
is($pt->is_https("$ENV{TEST_PROXY_HOST}:3128"), 1, 'is https');
is($pt->is_http("$ENV{TEST_PROXY_HOST}:3128"), 1, 'is http');
is($pt->is_socks4("$ENV{TEST_PROXY_HOST}:3128"), 0, 'is socks4 for http(s)');
is($pt->is_socks5("$ENV{TEST_PROXY_HOST}:3128"), 0, 'is socks5 for http(s)');

__END__

3proxy settings:
socks
proxy
