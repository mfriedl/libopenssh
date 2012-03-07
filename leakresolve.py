#!/usr/bin/env python

# Copyright (c) 2012 Damien Miller <djm@mindrot.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Resolve leak dump to backtraces

import sys
import getopt
import subprocess

TRIM_TRACE=True

def usage():
	print >> sys.stderr, "leakresolve.py -p executable < trace"
	sys.exit(1);

class LineResolver:
	"""Resolves addresses to source lines"""
	def __init__(self, executable):
		self.resolver = subprocess.Popen(
		    ["addr2line", "-e", executable, '-C', '-f'],
		    bufsize=1,				# line-buffered
		    stdin=subprocess.PIPE,
		    stdout=subprocess.PIPE,
		)
		self.cache = {}
	def resolve(self, addr):
		if addr not in self.cache:
			self.resolver.stdin.write(addr + "\n")
			func = self.resolver.stdout.readline()
			loc = self.resolver.stdout.readline()
			result = "%s: in %s()" % (loc.strip(), func.strip())
			self.cache[addr] = result
		return self.cache[addr]

class Leak:
	"""Represents a memory leak site"""
	def __init__(self, backtrace, resolver):
		self.backtrace = backtrace;
		self.resolver = resolver
		self.nleaks = 0
		self.nbytes = 0;
	def leak(self, nbytes):
		self.nbytes += nbytes
		self.nleaks += 1
	def __str__(self):
		s = "Leaked %d objects totalling %d bytes\n" % \
		    (self.nleaks, self.nbytes)
		s += "\n".join(map(self.resolver.resolve, self.backtrace))
		return s

class LeakTracker:
	"""Tracks all memory leaks"""
	def __init__(self, executable):
		self.resolver = LineResolver(executable)
		self.leaks = {}
	def addleak(self, nbytes, trace):
		if TRIM_TRACE:
			trace = trace[:-1]
		trace = tuple(trace)
		if trace not in self.leaks:
			leak = Leak(trace, self.resolver)
			self.leaks[trace] = leak
		self.leaks[trace].leak(nbytes)
	def _leakcmp(self, a, b):
		r = cmp(self.leaks[a].nleaks, self.leaks[b].nleaks)
		if r:
			return r
		return cmp(self.leaks[a].nbytes, self.leaks[b].nbytes)
	def __str__(self):
		s = "Memory leaks\n"
		s+= "------------\n"
		total_sites = 0
		total_leaks = 0
		total_bytes = 0
		for trace in sorted(self.leaks.keys(), cmp=self._leakcmp):
			s += str(self.leaks[trace]) + "\n\n"
			total_sites += 1
			total_leaks += self.leaks[trace].nleaks
			total_bytes += self.leaks[trace].nbytes
		s+= "Total: %d leaks from %d sites, containing %d bytes\n" % \
		    (total_leaks, total_sites, total_bytes)
		return s

def main():
	executable = None
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'hp:')
	except getopt.GetoptError:
		print >> sys.stderr, "Invalid commandline arguments"
		usage()
	for o, a in opts:
		if o in ('-h', '--help'):
			usage()
		if o in ('-p', '--program'):
			executable = a
			continue

	if not executable:
		print >> sys.stderr, "Missing executable name"
		usage();

	leaks = LeakTracker(executable)
	for line in sys.stdin:
		if line.startswith("LEAK "):
			leakinfo = line.split()
			if len(leakinfo) < 4 or leakinfo[3] != "TRACE":
				sys.stdout.write(line);
				continue
			backtrace = leakinfo[4:]
			nbytes = int(leakinfo[2])
			leaks.addleak(nbytes, backtrace)

	print leaks

if __name__ == '__main__': main()

