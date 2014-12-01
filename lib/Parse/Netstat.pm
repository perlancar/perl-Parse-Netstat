package Parse::Netstat;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat);

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of "netstat" command',
    description => <<'_',

This program support several flavors of netstat. The default flavor is `linux`.
See `--flavor` on how to set flavor.

Since different flavors provide different fields and same-named fields might
contain data in different format, please see the sample parse output for each
flavor you want to support and adjust accordingly.

_
    args => {
        output => {
            summary => 'Output of netstat command',
            description => <<'_',

This function only parses program's output. You need to invoke "netstat" on your
own.

_
            schema => 'str*',
            pos => 0,
            req => 1,
            cmdline_src => 'stdin_or_files',
        },
        flavor => {
            summary => 'Flavor of netstat',
            schema  => ['str*', in => ['linux', 'solaris', 'freebsd', 'win32']],
            default => 'linux',
            description => <<'_',

For Linux, it supports the output of `netstat -an` or `netstat -anp`.

For FreeBSD, it supports `netstat` or `netstat -an`.

For Solaris, it supports `netstat`.

For Windows, it supports `netstat` or `netstat -an` or `netstat -anp`.

_
        },
        tcp => {
            summary => 'Whether to parse TCP connections',
            schema  => [bool => default => 1],
        },
        udp => {
            summary => 'Whether to parse UDP connections',
            schema  => [bool => default => 1],
        },
        unix => {
            summary => 'Whether to parse Unix socket connections',
            schema  => [bool => default => 1],
        },
    },
    examples => [
        {
            src => 'netstat -anp | parse-netstat',
            src_plang => 'bash',
        },
    ],
};
sub parse_netstat {
    my %args = @_;

    my $output = $args{output} or return [400, "Please specify output"];
    my $tcp    = $args{tcp} // 1;
    my $udp    = $args{udp} // 1;
    my $unix   = $args{unix} // 1;
    my $flavor = $args{flavor} // 'linux';

    if ($flavor eq 'linux') {
        require Parse::Netstat::linux;
        Parse::Netstat::linux::parse_netstat(
            output=>$output, tcp=>$tcp, udp=>$udp, unix=>$unix);
    } elsif ($flavor eq 'freebsd') {
        require Parse::Netstat::freebsd;
        Parse::Netstat::freebsd::parse_netstat(
            output=>$output, tcp=>$tcp, udp=>$udp, unix=>$unix);
    } elsif ($flavor eq 'solaris') {
        require Parse::Netstat::solaris;
        Parse::Netstat::solaris::parse_netstat(
            output=>$output, tcp=>$tcp, udp=>$udp, unix=>$unix);
    } elsif ($flavor eq 'win32') {
        require Parse::Netstat::win32;
        Parse::Netstat::win32::parse_netstat(
            output=>$output, tcp=>$tcp, udp=>$udp);
    } else {
        return [400, "Unknown flavor '$flavor', please see --help"];
    }
}

1;
# ABSTRACT: Parse netstat output

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat);
 my $res = parse_netstat(output => join("", `netstat -anp`), flavor=>'linux');


=head1 SEE ALSO

Parse::Netstat::* for per-flavor notes and sample outputs.

L<App::ParseNetstat> provides a CLI for this module.
