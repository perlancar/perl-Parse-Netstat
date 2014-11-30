#!perl

use 5.010;
use strict;
use warnings;
use Parse::Netstat qw(parse_netstat parse_netstat_win);
use Test::More 0.98;

my $data = <<'_';
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
tcp        0      0 127.0.0.1:1027              0.0.0.0:*                   LISTEN      -
tcp        0      0 builder.localdomain:1028    *:*                         LISTEN
tcp        0      0 127.0.0.1:58159             0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:58160             0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:7634              0.0.0.0:*                   LISTEN      -
tcp        0      0 0.0.0.0:22                  0.0.0.0:*                   LISTEN      -
tcp        0      0 0.0.0.0:631                 0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN      1234/program with space
tcp        0      0 192.168.0.103:44922         1.2.3.4:143                 ESTABLISHED 25820/thunderbird-b
tcp6       0      0 ::1:1028                    :::*                        LISTEN      -
udp        0      0 0.0.0.0:631                 0.0.0.0:*                               -
udp        0      0 192.168.0.103:56668         0.0.0.0:*                               -
udp        0      0 192.168.0.103:52753         0.0.0.0:*                               8888/opera
udp6       0      0 :::42069                    :::*                                    -
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ]         DGRAM                    6906   -                   /var/spool/postfix/dev/log
unix  2      [ ACC ]     STREAM     LISTENING     650654 -                   /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
unix  2      [ ACC ]     STREAM     LISTENING     1121541 16933/kate 123     /tmp/orbit-s1/linc-4225-0-267d23358095e
_

sub test_parse {
    my (%args) = @_;
    my $name = $args{name};
    my $data = $args{data};

    subtest $name => sub {
        my $res;
        my $eval_err;
        eval {
            my %fargs = (output => $data, %{$args{args} // {}});
            if ($args{win}) {
                $res = parse_netstat_win(%fargs);
            } else {
                $res = parse_netstat(%fargs);
            }
        };
        $eval_err = $@;

        if ($args{dies}) {
            ok($eval_err, "dies");
        } else {
            ok(!$eval_err, "doesn't die") or diag $eval_err;
        }

        if (exists $args{status}) {
            is($res->[0], $args{status}, "result") or diag explain $res;
        }

        if ($res->[0] == 200) {
            my $parsed = $res->[2];
            my $conns  = $parsed->{active_conns};
            my $num_tcp  = grep {($_->{proto} // '') =~ /tcp[46]?/}  @$conns;
            my $num_udp  = grep {($_->{proto} // '') =~ /udp[46]?/}  @$conns;
            my $num_unix = grep {($_->{proto} // '') =~ /unix/} @$conns;
            if (defined $args{num_tcp}) {
                is($num_tcp, $args{num_tcp}, "num_tcp=$args{num_tcp}");
            }
            if (defined $args{num_udp}) {
                is($num_udp, $args{num_udp}, "num_udp=$args{num_udp}");
            }
            if (defined $args{num_unix}) {
                is($num_unix, $args{num_unix}, "num_unix=$args{num_unix}");
            }
        } else {
            ok(0, "result is not 200 ($res->[0])");
            diag explain $res;
        }

        if ($args{post_parse}) {
            $args{post_parse}->($res);
        }
    };
}

test_parse(name=>'all', data=>$data, num_tcp=>10, num_udp=>4, num_unix=>3);
test_parse(name=>'no tcp', data=>$data, args=>{tcp=>0}, num_tcp=>0, num_udp=>4, num_unix=>3);
test_parse(name=>'no udp', data=>$data, args=>{udp=>0}, num_tcp=>10, num_udp=>0, num_unix=>3);
test_parse(name=>'no unix', data=>$data, args=>{unix=>0}, num_tcp=>10, num_udp=>4, num_unix=>0);

subtest "freebsd 10.1" => sub {
    my $data = <<'_';
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 192.168.1.33.780       192.168.1.10.2049      CLOSE_WAIT
tcp4       0      0 192.168.1.33.632       192.168.1.10.2049      CLOSED
tcp4       0      0 127.0.0.1.6012         *.*                    LISTEN
tcp6       0      0 ::1.6012               *.*                    LISTEN
tcp4       0     52 192.168.1.33.22        192.168.1.10.41487     ESTABLISHED
tcp4       0      0 127.0.0.1.6011         *.*                    LISTEN
tcp6       0      0 ::1.6011               *.*                    LISTEN
tcp4       0      0 192.168.1.33.22        192.168.1.10.61223     ESTABLISHED
tcp4       0      0 127.0.0.1.6010         *.*                    LISTEN
tcp6       0      0 ::1.6010               *.*                    LISTEN
tcp4       0      0 192.168.1.33.22        192.168.1.10.18499     ESTABLISHED
tcp4       0      0 192.168.1.33.22        192.168.1.10.30712     ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 *.4949                 *.*                    LISTEN
tcp6       0      0 *.4949                 *.*                    LISTEN
tcp4       0      0 *.667                  *.*                    LISTEN
tcp6       0      0 *.896                  *.*                    LISTEN
tcp4       0      0 *.879                  *.*                    LISTEN
tcp6       0      0 *.879                  *.*                    LISTEN
tcp4       0      0 *.111                  *.*                    LISTEN
tcp6       0      0 *.111                  *.*                    LISTEN
udp4       0      0 *.682                  *.*
udp6       0      0 *.726                  *.*
udp6       0      0 *.948                  *.*
udp4       0      0 *.*                    *.*
udp4       0      0 *.879                  *.*
udp6       0      0 *.879                  *.*
udp6       0      0 *.*                    *.*
udp4       0      0 *.755                  *.*
udp4       0      0 *.111                  *.*
udp6       0      0 *.932                  *.*
udp6       0      0 *.111                  *.*
udp4       0      0 *.514                  *.*
udp6       0      0 *.514                  *.*
Active UNIX domain sockets
Address  Type   Recv-Q Send-Q    Inode     Conn     Refs  Nextref Addr
fffff80057aa11e0 stream      0      0        0        0        0        0
fffff80057aa12d0 stream      0      0        0        0        0        0
fffff8001b0bc5a0 stream      0      0 fffff80011150938        0        0        0 /tmp/ssh-52dQiqRzC4/agent.35116
fffff8001b0bc780 stream      0      0        0 fffff8001b0bcc30        0        0
fffff8001b0bcc30 stream      0      0        0 fffff8001b0bc780        0        0
fffff80002ad85a0 stream      0      0 fffff80030dfd760        0        0        0 /tmp/ssh-ZPrtis6Qgb/agent.21969
fffff8001b0bc2d0 stream      0      0        0 fffff80057aa10f0        0        0
fffff80057aa10f0 stream      0      0        0 fffff8001b0bc2d0        0        0
fffff80002ad82d0 stream      0      0        0 fffff80002ad84b0        0        0
fffff80002ad84b0 stream      0      0        0 fffff80002ad82d0        0        0
fffff800028b3960 stream      0      0 fffff800354e3588        0        0        0 /var/run/dbus/system_bus_socket
fffff80002ad8a50 stream      0      0        0 fffff80002ad8c30        0        0
fffff80002ad8c30 stream      0      0        0 fffff80002ad8a50        0        0
fffff80002ad91e0 stream      0      0 fffff80002f5b1d8        0        0        0 /tmp/ssh-EXvnWwxbk4/agent.750
fffff80002ad93c0 stream      0      0        0 fffff80002ad90f0        0        0
fffff80002ad90f0 stream      0      0        0 fffff80002ad93c0        0        0
fffff80002ad9780 stream      0      0 fffff800029db000        0        0        0 /var/run/rpcbind.sock
fffff80002ad9b40 stream      0      0 fffff800029a4000        0        0        0 /var/run/devd.pipe
fffff80002ad80f0 dgram       0      0        0 fffff80002ad9960        0 fffff80002ad94b0
fffff80002ad9000 dgram       0      0        0 fffff80002ad9870        0 fffff80002ad92d0
fffff80002ad94b0 dgram       0      0        0 fffff80002ad9960        0        0
fffff80002ad92d0 dgram       0      0        0 fffff80002ad9870        0 fffff80002ad9690
fffff80002ad9690 dgram       0      0        0 fffff80002ad9870        0 fffff80002ad95a0
fffff80002ad95a0 dgram       0      0        0 fffff80002ad9870        0        0
fffff80002ad9870 dgram       0      0 fffff80002b3e938        0 fffff80002ad9000        0 /var/run/logpriv
fffff80002ad9960 dgram       0      0 fffff80002b3eb10        0 fffff80002ad80f0        0 /var/run/log
fffff80002ad9a50 seqpac      0      0 fffff80002947ce8        0        0        0 /var/run/devd.seqpacket.pipe
_
    test_parse(name=>'all', data=>$data, num_tcp=>23, num_udp=>13, num_unix=>27);
};

$data = <<'_';

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
  c:\windows\system32\WS2_32.dll
  C:\WINDOWS\system32\RPCRT4.dll
  c:\windows\system32\rpcss.dll
  C:\WINDOWS\system32\svchost.exe
  -- unknown component(s) --
  [svchost.exe]

  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  [System]

  TCP    127.0.0.1:1027         0.0.0.0:0              LISTENING       1244
  [alg.exe]

  TCP    192.168.0.104:139      0.0.0.0:0              LISTENING       4
  [System]

  UDP    0.0.0.0:1025           *:*                                    1120
  C:\WINDOWS\system32\mswsock.dll
  c:\windows\system32\WS2_32.dll
  c:\windows\system32\DNSAPI.dll
  c:\windows\system32\dnsrslvr.dll
  C:\WINDOWS\system32\RPCRT4.dll
  [svchost.exe]

  UDP    0.0.0.0:500            *:*                                    696
  [lsass.exe]

_

test_parse(name=>'all win', win=>1, data=>$data, num_tcp=>4, num_udp=>2);

DONE_TESTING:
done_testing();
