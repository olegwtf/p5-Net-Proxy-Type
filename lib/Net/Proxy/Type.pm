package Net::Proxy::Type;

use strict;
use Exporter;
use Errno qw(EWOULDBLOCK);
use Carp;
use IO::Socket::INET qw(:DEFAULT :crlf);
use IO::Select;

use constant {
	UNKNOWN_PROXY => -1,
	DEAD_PROXY    =>  0,
	HTTP_PROXY    =>  1,
	SOCKS4_PROXY  =>  2,
	SOCKS5_PROXY  =>  4,
};

our $VERSION = '0.04';
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(HTTP_PROXY SOCKS4_PROXY SOCKS5_PROXY UNKNOWN_PROXY DEAD_PROXY);
our %EXPORT_TAGS = (types => [qw(HTTP_PROXY SOCKS4_PROXY SOCKS5_PROXY UNKNOWN_PROXY DEAD_PROXY)]);

our $CONNECT_TIMEOUT = 5;
our $WRITE_TIMEOUT = 5;
our $READ_TIMEOUT = 5;
our $URL = 'http://www.google.com/';
our $KEYWORD = 'google';
our %NAME = (
	UNKNOWN_PROXY, 'UNKNOWN_PROXY',
	DEAD_PROXY, 'DEAD_PROXY',
	HTTP_PROXY, 'HTTP_PROXY',
	SOCKS4_PROXY, 'SOCKS4_PROXY',
	SOCKS5_PROXY, 'SOCKS5_PROXY',
);

sub new
{
	my ($class, %opts) = @_;
	my $self = {};
	
	$self->{connect_timeout} = $opts{connect_timeout} || $opts{timeout} || $CONNECT_TIMEOUT;
	$self->{write_timeout} = $opts{write_timeout} || $opts{timeout} || $WRITE_TIMEOUT;
	$self->{read_timeout} = $opts{read_timeout} || $opts{timeout} || $READ_TIMEOUT;
	$self->{http_strict} = $opts{http_strict} || $opts{strict};
	$self->{socks4_strict} = $opts{socks4_strict} || $opts{strict};
	$self->{socks5_strict} = $opts{socks5_strict} || $opts{strict};
	$self->{url} = $opts{url} || $URL;
	($self->{host}) = $self->{url} =~ m!^https?://([^:/]+)! or croak('Incorrect url specified. Should be https?://[^:/]+');
	$self->{keyword} = $opts{keyword} || $KEYWORD;
	$self->{noauth} = $opts{noauth};
	
	bless $self, $class;
}

foreach my $key (qw(connect_timeout write_timeout read_timeout http_strict socks4_strict socks5_strict keyword noauth))
{ # generate sub's for get/set object properties using closure
      no strict 'refs';
      *$key = sub
      {
            my $self = shift;
      
            return $self->{$key} = $_[0] if defined $_[0];
            return $self->{$key};
      }
}

sub timeout
{ # set timeout for all operations
	my ($self, $timeout) = @_;
	
	$self->{connect_timeout} = $timeout;
	$self->{write_timeout} = $timeout;
	$self->{read_timeout} = $timeout;
}

sub strict
{ # set strict mode for all proxy types
	my ($self, $strict) = @_;
	
	$self->{http_strict} = $strict;
	$self->{socks4_strict} = $strict;
	$self->{socks5_strict} = $strict;
}

sub url
{ # set or get url
	my $self = shift;
	
	if(defined($_[0])) {
		($self->{host}) = $_[0] =~ m!^https?://([^:/]+)! or croak('Incorrect url specified. Should be https?://[^:/]+');
		return $self->{url} = $_[0];
	}
	
	return $self->{url};
}

sub get
{ # get proxy type
	my ($self, $proxyaddr, $proxyport, $checkmask) = @_;
	
	unless(defined($checkmask)) {
		# (host, port) or (host:port, [mask])
		if(my ($host, $port) = _parse_proxyaddr($proxyaddr)) {
			# (host:port, [mask])
			$checkmask = $proxyport;
			$proxyaddr = $host;
			$proxyport = $port;
		}
		elsif(!defined($proxyport)) {
			# (host) - no port defined - error
			return DEAD_PROXY;
		}
	}
	
	my @checkers = (HTTP_PROXY, \&is_http, SOCKS4_PROXY, \&is_socks4, SOCKS5_PROXY, \&is_socks5);
	my $con_time = 0;
	
	for(my $i=0; $i<@checkers; $i+=2) {
		if(defined($checkmask)) {
			unless($checkers[$i] & $checkmask) {
				next;
			}
		}
		
		my ($ok, $tmp_con_time) = $checkers[$i+1]->($self, $proxyaddr, $proxyport);
		if ($tmp_con_time > $con_time) {
			$con_time = $tmp_con_time;
		}
		
		if($ok) {
			return wantarray ? ($checkers[$i], $con_time) : $checkers[$i];
		}
		elsif(!defined($ok)) {
			return wantarray ? (DEAD_PROXY, $con_time) : DEAD_PROXY;
		}
	}
	
	return wantarray ? (UNKNOWN_PROXY, $con_time) : UNKNOWN_PROXY;
}

sub get_as_string
{ # same as get(), but return string
	my ($self, $proxyaddr, $proxyport, $checkmask) = @_;
	
	my $type = $self->get($proxyaddr, $proxyport, $checkmask);
	return $NAME{$type};
}

sub is_http
{ # check is this http proxy
	my ($self, $proxyaddr, $proxyport) = @_;
	
	my ($socket, $con_time) = $self->_create_socket($proxyaddr, $proxyport)
		or return;
	
	# simply do http request
	unless($self->_http_request($socket)) {
		goto IS_HTTP_ERROR;
	}
	
	my ($buf, $rc);
	unless($self->{http_strict}) {
		# simple check. does response begins from `HTTP'?
		$rc = $self->_read_from_socket($socket, $buf, 4);
		if(!$rc || $buf ne 'HTTP') {
			goto IS_HTTP_ERROR;
		}
	}
	else {
		# strict check. does response header contains keyword?
		unless($self->_is_strict_response($socket)) {
			goto IS_HTTP_ERROR;
		}
	}
	
	$socket->close();
	return wantarray ? (1, $con_time) : 1;
	
	IS_HTTP_ERROR:
		$socket->close();
		return wantarray ? (0, $con_time) : 0;
}

sub is_socks4
{ # check is this socks4 proxy
  # http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
	my ($self, $proxyaddr, $proxyport) = @_;
	
	my ($socket, $con_time) = $self->_create_socket($proxyaddr, $proxyport)
		or return;
		
	unless($self->_write_to_socket($socket, "\x04\x01" . pack('n', 80) . inet_aton($self->{host}) . "\x00")) {
		goto IS_SOCKS4_ERROR;
	}
	
	my ($buf, $rc);
	$rc = $self->_read_from_socket($socket, $buf, 8);
	if(!$rc || substr($buf, 0, 1) ne "\x00" || substr($buf, 1, 1) ne "\x5a") {
		goto IS_SOCKS4_ERROR;
	}
	
	if($self->{socks4_strict}) {
		unless($self->_http_request($socket)) {
			goto IS_SOCKS4_ERROR;
		}
		
		unless($self->_is_strict_response($socket)) {
			goto IS_SOCKS4_ERROR;
		}
	}
	
	$socket->close();
	return wantarray ? (1, $con_time) : 1;
	
	IS_SOCKS4_ERROR:
		$socket->close();
		return wantarray ? (0, $con_time) : 0;
}

sub is_socks5
{ # check is this socks5 proxy
  # http://tools.ietf.org/search/rfc1928
	my ($self, $proxyaddr, $proxyport) = @_;
	
	my ($socket, $con_time) = $self->_create_socket($proxyaddr, $proxyport)
		or return;
	
	unless($self->_write_to_socket($socket, "\x05\x01\x00")) {
		goto IS_SOCKS5_ERROR;
	}
	
	my ($buf, $rc);
	$rc = $self->_read_from_socket($socket, $buf, 2);
	unless($rc) {
		goto IS_SOCKS5_ERROR;
	}
	
	my $c = substr($buf, 1, 1);
	if($c eq "\x01" || $c eq "\x02" || $c eq "\xff") {
		# this is socks5 proxy with authentification
		if($self->{noauth} || $self->{socks5_strict}) {
			goto IS_SOCKS5_ERROR;
		}
	}
	else {
		if($c ne "\x00") {
			goto IS_SOCKS5_ERROR;
		}
		
		unless($self->_write_to_socket($socket, "\x05\x01\x00\x01" . inet_aton($self->{host}) . pack('n', 80))) {
			goto IS_SOCKS5_ERROR;
		}
		
		# minimum length of response is 10
		# it is not necessarily to read whole response
		$rc = $self->_read_from_socket($socket, $buf, 10);
		if(!$rc || substr($buf, 1, 1) ne "\x00") {
			goto IS_SOCKS5_ERROR;
		}
		
		if($self->{socks5_strict}) {
			unless($self->_http_request($socket)) {
				goto IS_SOCKS5_ERROR;
			}
		
			unless($self->_is_strict_response($socket)) {
				goto IS_SOCKS5_ERROR;
			}
		}
	}
	
	$socket->close();
	return wantarray ? (1, $con_time) : 1;
	
	IS_SOCKS5_ERROR:
		$socket->close();
		return wantarray ? (0, $con_time) : 0;
}

sub _http_request
{ # do http request for some host
	my ($self, $socket) = @_;
	$self->_write_to_socket($socket, 'GET ' . $self->{url} . ' HTTP/1.0'. CRLF . 'Host: ' . $self->{host} . CRLF . CRLF);
}

sub _is_strict_response
{ # to make sure about proxy type we will read response header and try to find keyword
  # without this check most of http servers may be recognized as http proxy, because its response after _http_request() begins from `HTTP'
	my ($self, $socket) = @_;
	my ($header, $rc, $buf, $http_ok);
	
	while(1) {
		$rc = $self->_read_from_socket($socket, $buf, 20);
		unless(defined($rc)) {
			last;
		}
		else {
			unless($http_ok) {
				if(index($buf, 'HTTP') != 0) {
					last;
				}
				
				$http_ok = 1;
			}
			
			$header .= $buf;
			if(index($header, $self->{keyword}) != -1) {
				# keyword found - ok
				return 1;
			}
				
			if($rc == 0) {
				# no more data in the socket, keyword not found
				last;
			}
				
			if(index($header, CRLF . CRLF) != -1) {
				# header received, but no keyword found
				last;
			}
				
			if(length($header) > 2000) {
				# hmm, too big header
				last;
			}
		}
	}
	
	return 0;
}

sub _write_to_socket
{ # write data to non-blocking socket; return 1 on success, 0 on failure (timeout or other error)
	my ($self, $socket, $msg) = @_;
	
	my $selector = IO::Select->new($socket);
	my $start = time();
	while(time() - $start < $self->{write_timeout}) {
		unless($selector->can_write(1)) {
			# socket couldn't accept data for now, check if timeout expired and try again
			next;
		}
		
		my $rc = $socket->syswrite($msg);
		if($rc > 0) {
			# reduce our message
			substr($msg, 0, $rc) = '';
			if(length($msg) == 0) {
				# all data successfully writed
				return 1;
			}
		}
		elsif($! != EWOULDBLOCK) {
			# some error in the socket; will return false
			last;
		}
	}
	
	return 0;
}

sub _read_from_socket
{ # read $limit bytes from non-blocking socket; return 0 if EOF, undef if error, bytes readed on success ($limit)
	my ($self, $socket, $limit) = @_[0,1,3];
	
	my $selector = IO::Select->new($socket);
	my $start = time();
	my $buf;
	$_[2] = ''; # clean buffer variable like sysread() do
	
	while($limit > 0 && time() - $start < $self->{read_timeout}) {
		unless($selector->can_read(1)) {
			# no data in socket for now, check if timeout expired and try again
			next;
		}
		
		my $rc = $socket->sysread($buf, $limit);
		if(defined($rc)) {
			# no errors
			if($rc > 0) {
				# reduce limit and modify buffer
				$limit -= $rc;
				$_[2] .= $buf;
				if($limit == 0) {
					# all data successfully readed
					return length($_[2]);
				}
			}
			else {
				# EOF in the socket
				return 0;
			}
		}
		elsif($! != EWOULDBLOCK) {
			last;
		}
	}
	
	return undef;
}

sub _create_socket
{ # trying to create non-blocking socket by proxy address; return valid socket on success, 0 or undef on failure
	my ($self, $proxyaddr, $proxyport) = @_;
	
	unless(defined($proxyport)) {
		($proxyaddr, $proxyport) = _parse_proxyaddr($proxyaddr)
			or return 0;
	}
	
	my $conn_start = time();
	my $socket = $self->_open_socket($proxyaddr, $proxyport)
		or return;
	
	return ($socket, time() - $conn_start);
}

sub _open_socket
{ # open non-blocking socket
	my ($self, $host, $port) = @_;
	my $socket = IO::Socket::INET->new(PeerHost => $host, PeerPort => $port, Timeout => $self->{connect_timeout}, Blocking => 0);
	
	return $socket;
}

sub _parse_proxyaddr
{ # parse proxy address like this one: localhost:8080 -> host=localhost, port=8080
	my ($proxyaddr) = @_;
	my ($host, $port) = $proxyaddr =~ /^([^:]+):(\d+)$/
		or return;
		
	return ($host, $port);
}

1;

__END__

=head1 NAME

Net::Proxy::Type - Get proxy type

=head1 SYNOPSIS

=over

 use strict;
 use Net::Proxy::Type;
 
 # get proxy type and print its name
 my $proxytype = Net::Proxy::Type->new();
 my $type = $proxytype->get('localhost:1111');
 warn 'proxy type is: ', $Net::Proxy::Type::NAME{$type};
 
 # same as
 warn 'proxy type is: ', Net::Proxy::Type->new()->get_as_string('localhost:1111');

=back

=over

 use strict;
 use Net::Proxy::Type ':types'; # import proxy type constants
 
 my $proxytype = Net::Proxy::Type->new(http_strict => 1); # strict check for http proxies - recommended
 my $proxy1 = 'localhost:1080';
 my $proxy2 = 'localhost:8080';
 my $proxy3 = 'localhost:3128';
 
 # check each type separately
 if($proxytype->is_http($proxy1)) {
 	warn "$proxy1 is http proxy";
 }
 elsif($proxytype->is_socks4($proxy1)) {
 	warn "$proxy1 is socks4 proxy";
 }
 elsif($proxytype->is_socks5($proxy1)) {
 	warn "$proxy1 is socks5 proxy";
 }
 else {
 	warn "$proxy1 is unknown proxy";
 }
 
 # get proxy type and do something depending returned value
 my $type = $proxytype->get($proxy2);
 if($type == HTTP_PROXY) {
 	warn "$proxy2 is http proxy";
 }
 elsif($type == SOCKS4_PROXY) {
 	warn "$proxy2 is socks4 proxy";
 }
 elsif($type == SOCKS5_PROXY) {
 	warn "$proxy2 is socks5 proxy";
 }
 elsif($type == DEAD_PROXY) {
 	warn "$proxy2 does not work";
 }
 else {
 	warn "$proxy2 is unknown proxy";
 }
 
 # return value of the "checker" methods is: 1 if type corresponds, 0 if not, undef if proxy server not connectable
 my $rv = $proxytype->is_http($proxy3);
 if($rv) {
 	warn "$proxy3 is http proxy";
 }
 elsif(defined($rv)) {
 	warn "$proxy3 is not http proxy, but it works";
 }
 else {
 	warn "$proxy3 doesn't work";
 }

=back

=head1 DESCRIPTION

The C<Net::Proxy::Type> is a module which can help you to get proxy type if you know host and port of the proxy server.
Supported proxy types for now are: http proxy, socks4 proxy and socks5 proxy.

=head1 METHODS

=over

=item Net::Proxy::Type->new( %options )

This method constructs new C<Net::Proxy::Type> object. Key / value pairs can be passed as an argument
to specify the initial state. The following options correspond to attribute methods described below:

   KEY                  DEFAULT                            
   -----------          -----------------------------------               
   connect_timeout      $Net::Proxy::Type::CONNECT_TIMEOUT
   write_timeout        $Net::Proxy::Type::WRITE_TIMEOUT
   read_timeout         $Net::Proxy::Type::READ_TIMEOUT 
   timeout              undef
   http_strict          undef
   socks4_strict        undef
   socks5_strict        undef
   strict               undef
   url                  $Net::Proxy::Type::URL
   keyword              $Net::Proxy::Type::KEYWORD
   noauth               undef

Description:

   connect_timeout - maximum number of seconds to wait until connection success
   write_timeout   - maximum number of seconds to wait until write operation success
   read_timeout    - maximum number of seconds to wait until read operation success
   timeout         - set value of all *_timeout options above to this value
   http_strict     - use or not strict method to check http proxies
   socks4_strict   - use or not strict method to check socks4 proxies
   socks5_strict   - use or not strict method to check socks5 proxies
   strict          - set value of all *_strict options above to this value (about strict checking see below)
   url             - url which header should be checked for keyword when strict mode enabled
   keyword         - keyword which must be found in the url header
   noauth          - if proxy works, but authorization required, then false will be returned if noauth has true value

=item $proxytype->get($proxyaddress, $checkmask=undef)

=item $proxytype->get($proxyhost, $proxyport, $checkmask=undef)

Get proxy type. Checkmask allows to check proxy only for specified types, its value can be any 
combination of the valid proxy types constants (HTTP_PROXY, SOCKS4_PROXY, SOCKS5_PROXY for now),
joined with the binary OR (|) operator. Will check for all types if mask not defined. In scalar
context returned value is proxy type - one of the module constants descibed below. In list context
returned value is an array with proxy type as first element and connect time in seconds as second.

Example:

  # check only for socks type
  # if it is HTTP_PROXY returned value will be UNKNOWN_PROXY
  # because there is no check for HTTP_PROXY
  my $type = $proxytype->get('localhost:1080', SOCKS4_PROXY | SOCKS5_PROXY);

=item $proxytype->get_as_string($proxyaddress, $checkmask=undef)

=item $proxytype->get_as_string($proxyhost, $proxyport, $checkmask=undef)

Same as get(), but returns string instead of constant. In all contexts returns only one value.

=item $proxytype->is_http($proxyaddress)

=item $proxytype->is_http($proxyhost, $proxyport)

Check is this is http proxy. Returned value is 1 if it is http proxy, 0 if it is not http proxy
and undef if proxy host not connectable or proxy address is not valid. In list context returns array
where second element is connect time (empty array if proxy not connectable).

=item $proxytype->is_socks4($proxyaddress)

=item $proxytype->is_socks4($proxyhost, $proxyport)

Check is this is socks4 proxy. Returned value is 1 if it is socks4 proxy, 0 if it is not socks4 proxy
and undef if proxy host not connectable or proxy address is not valid. In list context returns array
where second element is connect time (empty array if proxy not connectable).

=item $proxytype->is_socks5($proxyaddress)

=item $proxytype->is_socks5($proxyhost, $proxyport)

Check is this is socks5 proxy. Returned value is 1 if it is socks5 proxy, 0 if it is not socks5 proxy
and undef if proxy host not connectable or proxy address is not valid. In list context returns array
where second element is connect time (empty array if proxy not connectable).

=item $proxytype->timeout($timeout)

Set timeout for all operations. See constructor options description above

=item $proxytype->strict($boolean)

Set or unset strict checking mode. See constructor options description above

=back

Methods below gets or sets corresponding options from the constructor:

=over

=item $proxytype->connect_timeout

=item $proxytype->connect_timeout($timeout)

=item $proxytype->read_timeout

=item $proxytype->read_timeout($timeout)

=item $proxytype->write_timeout

=item $proxytype->write_timeout($timeout)

=item $proxytype->http_strict

=item $proxytype->http_strict($boolean)

=item $proxytype->socks4_strict

=item $proxytype->socks4_strict($boolean)

=item $proxytype->socks5_strict

=item $proxytype->socks5_strict($boolean)

=item $proxytype->url($url)

=item $proxytype->keyword($keyword)

=item $proxytype->noauth($boolean)

=back

=head2 STRICT CHECKING

How this module works? To check proxy type it simply do some request to the proxy server and checks response. Each proxy
type has its own response type. For socks proxies we can do socks initialize request and response should be as its
described in socks proxy documentation. For http proxies we can do http request to some host and check for example
if response begins from `HTTP'. Problem is that if we, for example, will check `yahoo.com:80' for http proxy this way,
we will get positive response, but `yahoo.com' is not a proxy it is a web server. So strict checking helps us to avoid this
problems. What we do? We send http request to the server, specified by the `url' option in the constructor via proxy and checks
if response header contains keyword, specified by `keyword' option. If there is no keyword in the header it means
that this proxy is not of the cheking type. This is not best solution, but it works. So strict mode recommended
to check http proxies if you want to cut off such "proxies" as `yahoo.com:80', but you can use it with other proxy types
too.

=head1 PACKAGE CONSTANTS AND VARIABLES

Following proxy type constants available and could be imported separately or together with `:types' tag:

=over

=item UNKNOWN_PROXY

=item DEAD_PROXY

=item HTTP_PROXY

=item SOCKS4_PROXY

=item SOCKS5_PROXY

=back

Following variables available (not importable):

=over

=item $CONNECT_TIMEOUT = 5

=item $WRITE_TIMEOUT = 5

=item $READ_TIMEOUT = 5

=item $URL = 'http://www.google.com/'

=item $KEYWORD = 'google'

=item %NAME

Dictionary between proxy type constant and proxy type name

=back

=head1 COPYRIGHT

Copyright 2010-2011 Oleg G <oleg@cpan.org>.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
