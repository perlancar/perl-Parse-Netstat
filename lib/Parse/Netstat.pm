package Parse::Netstat;

use 5.010001;
use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(parse_netstat parse_netstat_win);

# VERSION

our %SPEC;

$SPEC{parse_netstat} = {
    v => 1.1,
    summary => 'Parse the output of Unix "netstat" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without. And can be called with
`-p` (show PID/program names) or without.

For parsing output of Windows "netstat", see parse_netstat_win().

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
        tcp => {
            summary => 'Whether to parse TCP (and TCP6) connections',
            schema  => [bool => default => 1],
        },
        udp => {
            summary => 'Whether to parse UDP (and UDP6) connections',
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

    my @conns;
    my $i = 0;
    for my $line (split /^/, $output) {
        $i++;
        my %k;
        if ($line =~ /^tcp/ && $tcp) {
            #Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
            #tcp        0      0 0.0.0.0:8898                0.0.0.0:*                   LISTEN      5566/daemon2.pl [pa
            $line =~ m!^(?P<proto>tcp[46]?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+)\s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+) (?: \s+ (?:
                               (?P<pid>\d+)/(?P<program>.+?) |
                               -
                       ))? \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^udp/ && $udp) {
            #udp        0      0 0.0.0.0:631                 0.0.0.0:*                               2769/cupsd
            $line =~ m!^(?P<proto>udp[46]?) \s+ (?P<recvq>\d+) \s+ (?P<sendq>\d+)\s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+)? (?: \s+ (?:
                               (?P<pid>\d+)/(?P<program>.+?) |
                               -
                       ))? \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            %k = %+;
        } elsif ($line =~ /^unix/ && $unix) {
            #Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
            #    unix  2      [ ACC ]     STREAM     LISTENING     650654 30463/gconfd-2      /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
            $line =~ m!^(?P<proto>unix) \s+ (?P<refcnt>\d+) \s+
                       \[\s*(?P<flags>\S*)\s*\] \s+ (?P<type>\S+) \s+
                       (?P<state>\S+|\s+) \s+ (?P<inode>\d+) \s+
                       (?: (?: (?P<pid>\d+)/(?P<program>.+?) | - ) \s+)?
                       (?P<path>.*?)\s*$!x
                           or return [400, "Can't parse unix line (#$i): $line"];
            %k = %+;
        } else {
            next;
        }
        push @conns, \%k;
    }

    [200, "OK", {active_conns => \@conns}];
}

$SPEC{parse_netstat_win} = {
    v => 1.1,
    summary => 'Parse the output of Windows "netstat" command',
    description => <<'_',

Netstat can be called with `-n` (show raw IP addresses and port numbers instead
of hostnames or port names) or without. It can be called with `-a` (show all
listening and non-listening socket) option or without. It can be called with
`-o` (show PID) or without. And it can be called with `-b` (show executables) or
not.

For parsing output of Unix "netstat", see parse_netstat().

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
        tcp => {
            summary => 'Whether to parse TCP (and TCP6) connections',
            schema  => [bool => default => 1],
        },
        udp => {
            summary => 'Whether to parse UDP (and UDP6) connections',
            schema  => [bool => default => 1],
        },
    },
};
sub parse_netstat_win {
    my %args = @_;
    my $output = $args{output} or return [400, "Please specify output"];
    my $tcp    = $args{tcp} // 1;
    my $udp    = $args{udp} // 1;

    my @conns;
    my $i = 0;
    my $cur; # whether we're currently parsing TCP or UDP entry
    my $k;
    for my $line (split /^/, $output) {
        $i++;
        if ($line =~ /^\s*TCP\s/ && $tcp) {
            #  Proto  Local Address          Foreign Address        State           PID
            #  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
            #  c:\windows\system32\WS2_32.dll
            #  C:\WINDOWS\system32\RPCRT4.dll
            #  c:\windows\system32\rpcss.dll
            #  C:\WINDOWS\system32\svchost.exe
            #  -- unknown component(s) --
            #  [svchost.exe]
            #
            $line =~ m!^\s*(?P<proto>TCP6?) \s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?P<state>\S+) (?: \s+ (?:
                               (?P<pid>\d+)
                       ))? \s*$!x
                           or return [400, "Can't parse tcp line (#$i): $line"];
            $k = { %+ };
            $cur = 'tcp';
            for ($k->{proto}) { $_ = lc }
            push @conns, $k;
        } elsif ($line =~ /^\s*UDP\s/ && $udp) {
            #  UDP    0.0.0.0:500            *:*                                    696
            #  [lsass.exe]
            #
            # XXX state not yet parsed
            $line =~ m!^\s*(?P<proto>UDP6?) \s+
                       (?P<local_host>\S+?):(?P<local_port>\w+)\s+
                       (?P<foreign_host>\S+?):(?P<foreign_port>\w+|\*)\s+
                       (?: \s+ (?:
                               (?P<pid>\d+)
                       ))? \s*$!x
                           or return [400, "Can't parse udp line (#$i): $line"];
            $k = { %+ };
            $cur = 'udp';
            for ($k->{proto}) { $_ = lc }
            push @conns, $k;
        } elsif ($cur) {
            $k->{execs} //= [];
            next if $line =~ /^\s*--/; # e.g. -- unknown component(s) --
            next if $line =~ /^\s*can not/i; # e.g.  Can not obtain ownership information
            push @{ $k->{execs} }, $1 if $line =~ /^\s*(\S.*?)\s*$/;
            next;
        } else {
            # a blank line or headers. ignore.
        }
    }

    [200, "OK", {active_conns => \@conns}];
}

1;
# ABSTRACT: Parse the output of "netstat" command

=head1 SYNOPSIS

 use Parse::Netstat qw(parse_netstat parse_netstat_win);

 my $output = `netstat -anp`;
 my $res = parse_netstat output => $output;

Sample result:

 [
  200,
  "OK",
  {
    active_conns => [
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "127.0.0.1",
        local_port => 1027,
        proto => "tcp",
        recvq => 0,
        sendq => 0,
        state => "LISTEN",
      },
      ...
      {
        foreign_host => "0.0.0.0",
        foreign_port => "*",
        local_host => "192.168.0.103",
        local_port => 56668,
        proto => "udp",
        recvq => 0,
        sendq => 0,
      },
      ...
      {
        flags   => "ACC",
        inode   => 15631,
        path    => "\@/tmp/dbus-VS3SLhDMEu",
        pid     => 4513,
        program => "dbus-daemon",
        proto   => "unix",
        refcnt  => 2,
        state   => "LISTENING",
        type    => "STREAM",
      },
    ],
  }
 ]


=head1 SEE ALSO

=cut
