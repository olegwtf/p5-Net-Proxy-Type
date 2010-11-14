use 5.005000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::Proxy::Type',
    VERSION_FROM      => 'lib/Net/Proxy/Type.pm', # finds $VERSION
    PREREQ_PM         => { Exporter  => 0, IO::Socket::INET => 0, IO::Select => 0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/Proxy/Type.pm', # retrieve abstract from module
       AUTHOR         => 'Oleg G <oleg@cpan.org>') : ()),
);

