#!/usr/bin/perl

# net-proc-watch v1.0
# Real-time process-level network throughput using eBPF kernel probes.
# Copyright (c) 2023 PixlCore.com and Joseph Huckaby
# Released under the MIT License

use strict;
use warnings;
use Getopt::Long;
use IPC::Open2;
use JSON;

$| = 1;

# make sure we are root
if ($< != 0) { die("Error: Must be root to use this tool.\n"); }

# parse command-line args
my $format = '';
GetOptions( "format=s" => \$format );

# Spawn bidirectional bpftrace in JSON mode
my $out = undef;
my $in = undef;
my $pid = open2($out, $in, 'bpftrace -B none -f json -');

# Write our bpftrace script to child process
while (<DATA>) {
	print $in $_;
}
close($in);

# Print CSV header if applicable
if (!$format) { print("PID, COMMAND, CONNS, TX_SEC, RX_SEC\n"); }

# Continuously read NDJSON from child process
my $json = JSON->new->utf8;
my $line = undef;
my $conns = {};

while (<$out>) {
	eval { $line = $json->decode($_); };
	next if $@;
	
	if ($line->{type} eq 'map') {
		if ($line->{data}->{'@skcomm'}) { process_skcomm($line->{data}->{'@skcomm'}); }
		elsif ($line->{data}->{'@skpid'}) { process_skpid($line->{data}->{'@skpid'}); }
		elsif ($line->{data}->{'@sktx'}) { process_sktx($line->{data}->{'@sktx'}); }
		elsif ($line->{data}->{'@skrx'}) { process_skrx($line->{data}->{'@skrx'}); }
	}
	elsif ($line->{type} eq 'printf') {
		if ($line->{data} =~ /^TICK/) { tick(); }
		elsif ($line->{data} =~ /^CLOSE/) { process_close($line->{data}); }
	}
}

# Wait for the child process to finish
waitpid($pid, 0);

exit(0);

sub process_skcomm {
	# Map connections to process names
	# {"0xffff888004c71800": "curl"}
	my $data = shift;
	
	foreach my $id (keys %$data) {
		my $cmd = $data->{$id};
		my $conn = $conns->{$id} ||= {};
		$conn->{cmd} = $cmd;
	}
}

sub process_skpid {
	# Map connections to PIDs
	# {"0xffff888004c71800": 24280}
	my $data = shift;
	
	foreach my $id (keys %$data) {
		my $pid = $data->{$id};
		my $conn = $conns->{$id} ||= {};
		$conn->{pid} = $pid;
	}
}

sub process_sktx {
	# Track absolute transmit byte counts for connections
	# {"0xffff888004c71800": 121}
	my $data = shift;
	
	foreach my $id (keys %$data) {
		my $bytes = $data->{$id};
		my $conn = $conns->{$id} ||= {};
		
		$conn->{old_tx} = $conn->{tx} || 0;
		$conn->{tx} = $bytes;
	}
}

sub process_skrx {
	# Track absolute receive byte counts for connections
	# {"0xffff888004c71800": 203346}
	my $data = shift;
	
	foreach my $id (keys %$data) {
		my $bytes = $data->{$id};
		my $conn = $conns->{$id} ||= {};
		
		$conn->{old_rx} = $conn->{rx} || 0;
		$conn->{rx} = $bytes;
	}
}

sub process_close {
	# Process connection close event
	# CLOSE: 4c71800: PID 24280, curl, TX 121, RX 2863210, 19887 MS
	my $line = shift;
	if ($line !~ /^CLOSE\:\s+(\w+)\:\s+PID\s+(\d+)\,\s+([^\,]+)\,\s+TX\s+(\d+)\,\s+RX\s+(\d+)/) { return; }
	my ($id_frag, $pid, $cmd, $tx, $rx) = ($1, $2, $3, $4, $5);
	my $full_id = undef;
	
	# locate full socket ID using fragment (bpftrace only gives us a few hex chars in printf(%x) mode)
	foreach my $id (keys %$conns) {
		if ($id =~ /$id_frag$/) { $full_id = $id; last; }
	}
	if ($full_id) {
		# found, mark socket as closed
		$conns->{$full_id}->{closed} = 1;
	}
	else {
		# not found, create new stub, so it is accounted for in next tick report (short-lived socket)
		$conns->{$id_frag} = { pid => $pid, cmd => $cmd, old_tx => 0, tx => $tx, old_rx => 0, rx => $rx, closed => 1 };
	}
}

sub tick {
	# generate report every tick (second)
	my $procs = {};
	
	# aggregate conns by proc and calc tx/rx deltas
	foreach my $id (keys %$conns) {
		my $conn = $conns->{$id};
		next unless $conn->{pid} && $conn->{cmd};
		
		my $proc = $procs->{ $conn->{pid} } ||= { cmd => $conn->{cmd}, tx_sec => 0, rx_sec => 0, conns => 0 };
		$proc->{conns}++;
		if ($conn->{tx}) { $proc->{tx_sec} += ($conn->{tx} - $conn->{old_tx}); }
		if ($conn->{rx}) { $proc->{rx_sec} += ($conn->{rx} - $conn->{old_rx}); }
	}
	
	# print in human-readable or JSON format
	if ($format eq 'json') {
		print $json->encode($procs) . "\n";
	}
	else {
		print("\n");
		foreach my $pid (keys %$procs) {
			my $proc = $procs->{$pid};
			print join(', ', $pid, $proc->{cmd}, $proc->{conns}, nice_bytes($proc->{tx_sec}) . "/sec", nice_bytes($proc->{rx_sec}) . "/sec") . "\n";
		}
	}
	
	# prune closed sockets
	foreach my $id (keys %$conns) {
		if ($conns->{$id}->{closed}) { delete $conns->{$id}; }
	}
}

sub nice_bytes {
	# Given raw byte value, return text string such as '5.6 MB' or '79 K'
	my $bytes = shift;
	
	if ($bytes < 1024) { return $bytes . ' bytes'; }
	else {
		$bytes /= 1024;
		if ($bytes < 1024) { return short_float($bytes) . ' K'; }
		else {
			$bytes /= 1024;
			if ($bytes < 1024) { return short_float($bytes) . ' MB'; }
			else {
				$bytes /= 1024;
				if ($bytes < 1024) { return short_float($bytes) . ' GB'; }
				else {
					$bytes /= 1024;
					return short_float($bytes) . ' TB';
				}
			}
		}
	}
}

sub short_float {
	# Shorten floating-point decimal to 2 places, unless they are zeros.
	my $f = shift;
	
	$f =~ s/^(\-?\d+\.[0]*\d{2}).*$/$1/;
	return $f;
}

__DATA__

/*
 * Adapted from tcplife.bt, BPF Performance Tools, Chapter 10.
 * Copyright (c) 2019 Brendan Gregg.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * This was originally created for the BPF Performance Tools book
 * published by Addison Wesley. ISBN-13: 9780136554820
 * When copying or porting, include this comment.
 *
 * 17-Apr-2019  Brendan Gregg   Created this.
 * 28-Dec-2023  Joseph Huckaby  Adapted for net-proc-watch.
 */

#ifndef BPFTRACE_HAVE_BTF
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#else
#include <sys/socket.h>
#endif

kprobe:tcp_set_state
{
	$sk = (struct sock *)arg0;
	$newstate = arg1;
	
	/*
	 * This tool includes PID and comm context. From TCP this is best
	 * effort, and may be wrong in some situations. It does this:
	 * - record timestamp on any state < TCP_FIN_WAIT1
	 *	note some state transitions may not be present via this kprobe
	 * - cache task context on:
	 *	TCP_SYN_SENT: tracing from client
	 *	TCP_LAST_ACK: client-closed from server
	 * - do output on TCP_CLOSE:
	 *	fetch task context if cached, or use current task
	 */

	// record first timestamp seen for this socket
	if ($newstate < 4 && @birth[$sk] == 0 && pid > 0) {
		@birth[$sk] = nsecs;
	}

	// record PID & comm on SYN_SENT
	if (($newstate == 2 || $newstate == 9) && @birth[$sk]) {
		@skpid[$sk] = pid;
		@skcomm[$sk] = comm;
	}
	
	// session ended: calculate lifespan and print
	if ($newstate == 7 && @birth[$sk]) {
		$delta_ms = (nsecs - @birth[$sk]) / 1e6;
		$tp = (struct tcp_sock *)$sk;
		$pid = @skpid[$sk];
		$comm = @skcomm[$sk];
		if ($comm == "") {
			// not cached, use current task
			$pid = pid;
			$comm = comm;
		}
		
		printf("CLOSE: %x: PID %d, %s, TX %d, RX %d, %d MS\n", $sk, $pid, $comm, $tp->bytes_acked, $tp->bytes_received, $delta_ms);
		
		delete(@birth[$sk]);
		delete(@skpid[$sk]);
		delete(@skcomm[$sk]);
		delete(@sktx[$sk]);
		delete(@skrx[$sk]);
	}
}

kprobe:tcp_sendmsg,
kprobe:tcp_recvmsg
{
	$sk = (struct sock *)arg0;
	
	if (@birth[$sk]) {
		$tp = (struct tcp_sock *)$sk;
		@sktx[$sk] = $tp->bytes_acked;
		@skrx[$sk] = $tp->bytes_received;
	}
}

interval:s:1
{
	print(@skcomm);
	print(@skpid);
	print(@sktx);
	print(@skrx);
	printf("TICK\n");
}

END
{
	clear(@birth); clear(@skpid); clear(@skcomm); clear(@sktx); clear(@skrx);
}
