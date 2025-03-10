## pingem
I frequently leave ping running in a terminal so I have something to visually
query when real-time comms start misbehaving. If Zoom starts misbehaving, a quick
glance at a running ping will tell me if something has gone wrong with my net
connection, or if the issue is on the other end. These are the kinds of paranoid
habits you develop when you're no AT&T "broadband."

I wanted something a little more long-term, though. Something that would show me
a longer-term history of my connection state. I created a tool called pingstats,
that did just this for me, but it suffered from the requirement that it run in
iTerm2. I love iTerm2, it's amazing, but it's Mac only. I wanted a solution that
would make it possible to put out a presentable visual and simplify the process
of providing a UI.

The natural choice for UI work is JavaScript - even though I'm not really a fan.
Unfortunately, JS has no ability to send ICMP packets, nor can it invoke Ping.
Maybe this would be possible with NodeJS, but I really wanted this tool to be
something that had a minimal barrier to installation. Expecting someone to have
Node on their machine is a bit of a stretch. Python and a web browser are far
more realistic expectations.

# What's With user_icmp.py? 

Calling /usr/bin/ping for ICMP is fairly simple and gets us 99% of what we need,
but there's an edge case that precludes using any of the ping binaries available
in linux, OSX, or Windows: you have no idea when a packet was sent.

This seems like a minor issue, but it led to an issue that couldn't be solved
or worked around. The ping binaries will only tell you when a packet arrives.
It will not tell you where it is in terms of what has been sent. If you
experience a long bout of packet loss, you can only guess which ICMP sequences'
ids have been sent. You would guess that, given the interpacket interval I,
packet number X would be sent at time X*I. This is not the case. Each packet is
sent after the previous packet is successfully queued and AT LEAST I seconds
have elapsed.

This means that you can end up in a situation were the graph displays a long
bout of packet loss, but packets that were thought to be lost in the distant
past start arriving in the present. The UI can go back to historic metrics and
remove the reported lost packet, but this leads to a couple other issues. First,
what happens if an epoch (a column in the history) has its last packet removed?
Do we display that as 100% packet loss or as no data? I would opt to mark it as
100% loss, but there are times that this is not ideal. Secondly, what happens if
we lose 0-1000, then receive 1001, and lose 1002? We've already marked 1002 as
lost at some point in the distant past and it won't be re-recorded as lost in
the current epoch. When 1001 arrives, do we mark everything after it as in
transit and start over with determining what has timed out and what hasn't?

It's a lot of silly heuristics and guesswork that end up making for some very
convoluted edge cases in the code that make for lots of cross-interaction and
difficult debugging. I'd rather just know exactly when packet number 1000 was
sent.

There are a couple options here: 1) wrap tcpdump. 2) rewrite ping. Given that I
hate how limiting ping is, I find it a far preferable solution to provide a
service that will respond to user requests and mediate ICMP traffic on the
users' bahalf.  The user can only request pings and will only receive info
about when those pings are sent and when their responses arrive. As a bonus, we
can have icmp_seq ids that are as wide as we like. I chose 8 bytes because
we're padding packets anyway, so there's little point in saving space. I
dislike the heuristic that I had to create for turning 16-bit sequence ids into
arbitrarily wide ones. Sooner or later it was going to bug out on me.

