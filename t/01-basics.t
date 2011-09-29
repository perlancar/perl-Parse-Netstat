#!perl

use 5.010;
use strict;
use warnings;
use Parse::Netstat qw(parse_netstat);
use Test::More 0.96;

my $data = <<'_';
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name
tcp        0      0 127.0.0.1:1027              0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:48397             0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:58159             0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:58160             0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:7634              0.0.0.0:*                   LISTEN      -
tcp        0      0 0.0.0.0:22                  0.0.0.0:*                   LISTEN      -
tcp        0      0 0.0.0.0:631                 0.0.0.0:*                   LISTEN      -
tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN      -
tcp        0      0 192.168.0.103:44922         1.2.3.4:143                 ESTABLISHED 25820/thunderbird-b
udp        0      0 0.0.0.0:631                 0.0.0.0:*                               -
udp        0      0 192.168.0.103:56668         0.0.0.0:*                               -
udp        0      0 192.168.0.103:52753         0.0.0.0:*                               8888/opera
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ]         DGRAM                    6906   -                   /var/spool/postfix/dev/log
unix  2      [ ACC ]     STREAM     LISTENING     650654 -                   /tmp/orbit-t1/linc-76ff-0-3fc1dd3f2f2
unix  2      [ ACC ]     STREAM     LISTENING     1121541 16933/kate          /tmp/orbit-s1/linc-4225-0-267d23358095e
_

sub test_parse {
    my (%args) = @_;
    my $name = $args{name};
    my $data = $args{data} // $data;

    subtest $name => sub {
        my $res;
        my $eval_err;
        eval { $res = parse_netstat(output => $data, %{$args{args} // {}}) };
        $eval_err = $@;

        if ($args{dies}) {
            ok($eval_err, "dies");
        } else {
            ok(!$eval_err, "doesn't die") or diag $eval_err;
        }

        if (exists $args{status}) {
            is($res->[0], $args{status}, "result");
        }

        if ($res->[0] == 200) {
            my $parsed = $res->[2];
            my $conns  = $parsed->{active_conns};
            my $num_tcp  = grep {$_->{proto} eq 'tcp'}  @$conns;
            my $num_udp  = grep {$_->{proto} eq 'udp'}  @$conns;
            my $num_unix = grep {$_->{proto} eq 'unix'} @$conns;
            if (defined $args{num_tcp}) {
                is($num_tcp, $args{num_tcp}, "num_tcp=$args{num_tcp}");
            }
            if (defined $args{num_udp}) {
                is($num_udp, $args{num_udp}, "num_udp=$args{num_udp}");
            }
            if (defined $args{num_unix}) {
                is($num_unix, $args{num_unix}, "num_unix=$args{num_unix}");
            }
        }

        if ($args{post_parse}) {
            $args{post_parse}->($res);
        }
    };
}


test_parse(name=>'all', num_tcp=>9, num_udp=>3, num_unix=>3);
test_parse(name=>'no tcp', args=>{tcp=>0}, num_tcp=>0, num_udp=>3, num_unix=>3);
test_parse(name=>'no udp', args=>{udp=>0}, num_tcp=>9, num_udp=>0, num_unix=>3);
test_parse(name=>'no unix', args=>{unix=>0}, num_tcp=>9, num_udp=>3, num_unix=>0);

DONE_TESTING:
done_testing();
