## pingem ...and this is how I discovered that my neighbors are flooding the
wifi bands so badly that it's severely impacting my service. It's across all
bands, so I'm in the process of dragging cable everywhere.  ![Current
Screenshot](/screenshot.png)
# Installing/running
The ICMP agent is now `user_icmp`, a small C++11 daemon (Linux only). Build it
and start it as root:

    cd user_icmp
    make
    sudo ./user_icmp

It needs root for exactly one thing: opening a raw ICMP socket. It opens that
socket, opens its listening socket (127.0.0.1:8000 only), and then permanently
drops to `nobody` before it reads a single byte from anyone. Everything else -
the HTTP parsing, DNS, all client input - runs unprivileged. (Instead of sudo,
you can `sudo setcap cap_net_raw+ep user_icmp` and run it as yourself.)

Options:
* `--port N` - TCP port on 127.0.0.1 (default 8000)
* `--user NAME` - who to become after startup (default nobody)
* `--min-interval S` - fastest any client may ping a target (default 0.1 s)
* `--reply-expiry S` - forget unanswered packets after this long (default 60 s)

The old Python agent, user_icmp2.py, still works and speaks the same protocol,
but it runs entirely as root and is on its way out.

# The graphical client
`clients/pingem` is a native OpenGL client (SDL2 + Dear ImGui) that talks to
user_icmp over a Unix socket. It's replacing pingem.html, and it runs from the
command line:

    sudo apt install libsdl2-dev               # build dependency
    cd clients
    make
    ./pingem 192.168.1.1 8.8.8.8 amazon.com     # --interval S, --size N, --flows K

Controls: the mouse wheel over a graph zooms around the mouse pointer;
left-click and drag scrubs through time (the epoch you grab stays under the
mouse); End (or F) goes back to following "now"; the View button (or V)
switches the summary column between "combined" and "by flow"; Q or Escape
quits. If user_icmp isn't running, or restarts, the client keeps retrying and
picks up where it left off; the outage shows as a gap.

## Flows, and how to read the "by flow" view

(The screenshots in this section are from simulations - see "About the
example images" at the end of the section.)

**The question flows answer.** Look at the histogram in the summary column
(the bars on the right of each row: one bar per latency range, longer bar =
more replies took that long). Often it isn't one smooth hump. It can have two
or more separate humps with a gap between them - say a pile of replies around
14 ms, another pile around 17 ms, and few in between. We'll call each hump a
*clump*. A clump means "there are distinct ways a packet can be delayed, and
each packet gets one of them". The question is: what are those distinct ways?

![Two clumps](docs/images/combined_two_clumps.png)

*Two clumps. The graph on the left shows two horizontal bands of replies -
one around 4 ms, one around 10 ms - and the histogram on the right has a
hump for each.*

One common answer is that your packets are taking different routes. Between
you and a big site there are often several parallel paths, and routers spread
traffic over them. Usually they pick the path by hashing fields of the packet
header - so all packets that look the same go the same way, and a slower path
would show up as its own clump.

**What a flow is.** pingem spreads each host's pings over 8 *flows* (round
robin: ping 1 is flow 0, ping 2 is flow 1, ... ping 9 is flow 0 again). Every
ping in a flow is built to have the same ICMP checksum, and the flows have
different checksums. Routers that hash the checksum to pick a path will
therefore send every ping in a flow down the same path - but different flows
may go different ways.

**The "by flow" view.** Click View (or press V) and each row's summary column
splits into 8 small histograms, one per flow, numbered 0-7 underneath, all on
the same scale. Hover over one for its statistics; click it to highlight that
flow in the graph (everything else dims, including the other flows' share of
each loss bar).

![Hovering over a flow](docs/images/by_flow_tooltip.png)

*The by-flow view with flow 3 highlighted: its replies stay bright in the
graph, the rest dim. The tooltip and the numbers in the top right corner are
flow 3's own statistics.*

Now compare the clumps across the 8 histograms:

    Each flow has ONE of the clumps -       Every flow has BOTH clumps -
    the clumps "sort cleanly by flow":      they don't sort by flow:

    flow:  0  1  2  3  4  5  6  7           flow:  0  1  2  3  4  5  6  7
    17ms      #     #        #  #           17ms   #  #  #  #  #  #  #  #
    14ms   #     #     #  #                 14ms   #  #  #  #  #  #  #  #

* **Each flow has only one of the clumps** (left). Flows 1, 3, 6 and 7 always
  take about 17 ms; flows 0, 2, 4 and 5 always take about 14 ms. Since a
  flow's packets all follow one path, and a flow never shows the other clump,
  the clumps *are* the paths: you're being load-balanced over two routes and
  one is about 3 ms slower. (Which flows land where is effectively random -
  it depends on each router's hash.)

  ![Each flow in one clump](docs/images/by_flow_sorted.png)

  *Flows 0, 2, 4 and 5 sit only in the fast clump; 1, 3, 6 and 7 only in the
  slow one. Two routes.*

  Highlighting one of the slow flows confirms it: its replies all fall in
  the upper band, and only its share of each loss bar stays bright - in this
  simulation the slow route is also the one dropping packets.

  ![A slow flow highlighted](docs/images/by_flow_highlight.png)
* **Every flow has both clumps** (right). Packets that took the same path -
  same flow - still split into both clumps, so the second clump comes from
  something that varies packet by packet, not from routing. Usual suspects:
  your access link (cable modems wait for permission to transmit on a fixed
  schedule; Wi-Fi retransmits), a busy queue somewhere, or the far end. To
  find out where, add a row for each hop along the way (your router, your
  ISP's first router, ...) and see at which hop the second clump first
  appears. One caveat: if the routers on your path ignore the checksum when
  balancing ICMP (some hash only addresses), flows can't separate paths and
  you'll see this picture even if there are several routes. The route
  tracing planned below will tell those two cases apart.

  ![Every flow in both clumps](docs/images/by_flow_both.png)

  *All eight flows show both clumps: the delay is chosen per packet, not per
  route.*
* **Something in between** - some flows with one clump, some with both - can
  mean several balancers in a row, or one that spreads individual packets
  rather than flows.

  ![Some flows in one clump, some in both](docs/images/by_flow_mixed.png)

  *Flows 0 and 7 only in the fast clump, 1 and 4 only in the slow one, the
  rest in both.*

`--flows 0` turns flows off and lets the checksum vary with every packet, as
plain ping does (and then routers may scatter your pings over all the paths).

**About the example images.** They're real pingem screenshots, but of
simulated networks: `docs/tools/fake_responder.py` answers pings to
127.0.0.2-5 with made-up delays (two routes chosen by checksum, delays chosen
per packet, and so on), so each situation can be shown on demand. Its header
says how to run it to regenerate the images. The odd stray reply far above
the bands is the simulator's own timing noise.

The Unix socket speaks a plain-text line protocol (documented in
shared/protocol.h), so you can also drive user_icmp by hand:

    socat - ABSTRACT-CONNECT:user_icmp
    add 1 8.8.8.8 interval=1

# The browser page (being retired)
From there, just open the .html in a browser on the same machine as user_icmp2.
The url accepts some parameters;
* endpoints is a comma-separated list of ping targets.
* interval is the time delay between icmp packets to each endpoint. The default
  is 1 second, and that's a good default - see "Be gentle" below.
* packet_size is pretty easy to figure out. (The minimum is currently around 32)

So:
  file:///home/me/pingem/pingem.html?endpoints=192.168.1.1,8.8.8.8&interval=0.5
...will give you a track of network behavior to your local router... or
whatever.

# Purpose
I frequently leave ping running in a terminal so I have something to visually
query when real-time comms start misbehaving. If Zoom starts jittering, a quick
glance at a running ping will tell me if something has gone wrong with my net
connection or if the issue is on the other end. These are the kinds of paranoid
habits you develop when you're on AT&T "broadband."

I wanted something a little more long-term, though. Something that would show
me a longer-span history of my connection state. I created a tool called
pingstats that did just this for me, but it suffered from the restriction that
it could only run in iTerm2. I love iTerm2, it's amazing, but it's Mac only. I
wanted a solution that would make it possible to put out a presentable visual
and simplify the process of providing a UI.

The natural choice for UI work is JavaScript - even though I'm not really a
fan.  Unfortunately, JS has no ability to send ICMP packets, nor can it invoke
Ping.  ~~Maybe this would be possible with NodeJS~~ (it's not), but I really
wanted this tool to be something that had a minimal barrier to installation.
Expecting someone to have Node on their machine is a bit of a stretch. Python
and a web browser are far more realistic expectations. (Come to think of it -
maybe the "minimal barrier" requirement suggests that I should leave user_icmp
in Python? Ugh. Decisions.)

# What's With user_icmp.py?

Calling /usr/bin/ping for ICMP is fairly simple and gets us 99% of what we
need, but there's an edge case that precludes using any of the ping binaries
available in linux, OSX, or Windows. It all comes down to the fact that with
ping, you have no idea when a packet was sent.

This seems like a minor issue, but it led to an issue that couldn't be solved
or worked around. The ping binaries will only tell you when a packet arrives.
If you experience a long bout of packet loss, you can only guess which ICMP
sequence ids have been sent. You might assume that, given the interpacket
interval I, packet number X would be sent at time X*I. This is not the case.
Each packet is sent after the previous packet is successfully queued and AT
LEAST I seconds have elapsed.

This means that you can end up in a situation were the graph displays a long
bout of packet loss, but packets that were thought to be lost in the distant
past start arriving in the present. The UI can go back to historic metrics and
remove the reported lost packet, but this leads to a couple other issues.
First, what happens if an epoch (a column in the history) has its last packet
removed?  Do we display that as 100% packet loss or as no data? I would opt to
mark it as 100% loss, but there are times that this is not ideal. Secondly,
what happens if we lose icmp_sequence 0-1000, then receive 1001, and lose 1002?
We've already marked 1002 as lost at some point in the distant past and it
won't be re-recorded as lost in the current epoch. When 1001 arrives, do we
mark everything after it as in transit and start over with determining what has
timed out and what hasn't?

It's a lot of silly heuristics and guesswork that end up making for some very
convoluted edge cases in the code that make for lots of cross-interaction and
difficult debugging. I'd rather just know exactly when packet number 1000 was
sent.

There are a couple options here.

Option #1 is to wrap tcpdump with a minimal setuid process and continue using a
ping subprocess. A setuid root executable that reports just the icmp packets
that are associated with the user's sessions is attractive, but suffers from a
fatal flaw. When the network we're trying to reach is unavailable, no packet is
sent and we're back to guessing when icmp_seq # n was supposed to have been
sent.

Option #2 is to provide a service - also setuid - that the user can connect to
that will send and receive icmp traffic on the user's behalf. This allows us a
number of advantages. First, we can pack a wider icmp_seq in our custom-built
icmp packets. This is very convenient when you are sending millions of packets
and don't want to compensate for the default 16-bit ids. Second, even during a
total network outage we will still track icmp traffic that _should_ have been
sent, even if it wasn't. (When there's "no route to host", the ping executable
stops sending packets.) Basically, a network outage should look the same to the
user as any other string of losses. If this service includes a connection
method that can be reached by a browser running javascript, the project reduces
down to only two parts instead of the original three.

Hence, the rewrite. I went with option #2. The Python version could only ever
run as root, so it has now been rewritten in C++ (user_icmp/), which drops root
immediately after opening its raw socket.

A few things the C++ agent does differently:
* Packets carry only a 16-bit identifier and 16-bit sequence number for
  matching; the 64-bit sequence number and send time stay in the agent's table
  of outstanding packets. Those 8 header bytes are what every router must quote
  back in an ICMP error, so nothing depends on a payload surviving the trip.
* Every packet is scheduled individually and never sent in bursts. If the agent
  falls behind it skips ahead rather than catching up.
* A target dies the moment its browser connection closes. (The Python agent
  kept pinging orphaned targets forever.)
* The agent is the only clock: it timestamps pings when sent and replies when
  received, and the page no longer overwrites those timestamps.

# Be gentle
Everything on the path between you and a target has queues. Back-to-back
packets can fill one and cause the loss you're trying to measure, and routers
treat ICMP aimed at their own CPUs as low priority and rate-limit it. A ping a
second per target tells you nearly everything a ping every 100 ms does.


# Route characterization and hop latency (design notes - not built yet)

The plan: alongside its regular pings, user_icmp will send occasional
TTL-limited probes to discover the route(s) to each target, the same way
traceroute does. Two ideas from Paris traceroute make this work in the presence
of load balancing:

* **Flows.** Routers that spread traffic over parallel links mostly choose the
  link by hashing header fields - for ICMP, that includes the ICMP checksum.
  If we hold the checksum constant (by adjusting two "fudge" bytes in the
  payload to cancel out the changing sequence number), every packet in that
  "flow" takes the same forward path. Use several different fixed checksums and
  you get several flows, which may take different paths.
* **Probes share their flow's checksum,** so a TTL-limited probe follows the
  same path as the ordinary pings in its flow. That's what lets the main graph
  be colored by route: every reply belongs to a known flow, and every flow maps
  to a discovered path.

The rest of this section is about the hard part: deciding what the per-hop
round trip times are actually telling you.

## Why per-hop RTTs lie

A router forwards traffic in specialized hardware (the "data plane" or "fast
path"). When a probe's TTL runs out at a router, though, the reply - an ICMP
Time Exceeded - has to be **generated**, and that happens on the router's
general-purpose CPU (the "control plane" or "slow path"). That CPU's real job
is running routing protocols, so it treats generating ICMP as a low-priority
chore, and RFC 1812 section 4.3.2.8 explicitly allows routers to rate-limit
the ICMP errors they generate. Pinging a router's own address directly doesn't
help; that's answered by the same CPU.

So the RTT we measure to hop k is

    forward forwarding delay to k
      + time for k's CPU to get around to replying
      + delay of the reply on ITS way back (which may be a different path again)

The middle term is noise as far as your traffic is concerned. Traffic passing
*through* router k never waits on its CPU. The classic symptom is a hop that
shows 80 ms while every hop after it shows 20 ms. That's impossible if the 80
ms were real forwarding delay, because every later hop's packets went through
router k too.

Two tests try to separate real delay from slow-responder noise. Both rest on
the same ground rules:

1. **Only compare hops on the same forward path.** That means hops observed by
   flows that map to the same path, and never pooling probes across paths.
2. **Compare samples taken at the same time.** Probes rotate through every
   (flow, TTL) pair, so the samples for hop k and hop k+1 are interleaved over
   the same period. Never compare hop k from this morning with hop k+1 from
   this afternoon.
3. **Use rank-based statistics.** RTT distributions are skewed, have long tails
   and often several peaks (see the screenshot). Means and standard deviations
   describe them badly, and tests that assume a normal distribution are
   unreliable here. Everything below works on ranks or medians.
4. **Don't trust the minimum.** It's tempting because CPU delay only ever adds
   time, but it's a single sample, and the more hops there are, the more ways
   one lucky packet can produce an unrepresentative minimum. A low percentile
   (the 10th, say) keeps most of the benefit and is far more stable.

## Test 1: the downstream comparison

**Principle:** forwarding delay is cumulative. Any delay a packet suffers
being forwarded through router k is also suffered by every probe that
continues past k. So for the same path, hop k+1's RTTs should be no lower than
hop k's, apart from noise. If hop k's RTTs are reliably *higher* than hop
k+1's, the excess can't be forwarding delay. It's k's slow path, and we should
mark k as a "slow responder" rather than a bottleneck.

**The test: Mann-Whitney U (also called the Wilcoxon rank-sum test).** We have
n RTT samples for hop k (X) and m for a later hop (Y). The question is whether
a randomly chosen X tends to be larger than a randomly chosen Y.

1. Pool all n+m samples and rank them from smallest to largest (rank 1 =
   smallest). Tied values get the average of the ranks they span.
2. Let R be the sum of the ranks of the X samples.
3. U = R - n(n+1)/2. U counts, over all n*m (x, y) pairs, how many have x > y,
   with ties counting one half.
4. **Effect size:** A = U / (n*m) estimates P(X > Y). A = 0.5 means no
   tendency either way. A = 0.8 means hop k's RTT beats hop k+1's in 80% of
   pairings. This number is easy to read and matters more than the p-value
   (see the pitfalls).
5. **Significance**, for n and m above about 20 each, uses the normal
   approximation:

       mean(U) = n*m/2
       var(U)  = (n*m/12) * [ (n+m+1) - sum(t^3 - t) / ((n+m)(n+m-1)) ]

   where the sum runs over groups of tied values, each of size t. (With
   microsecond timestamps, exact ties are rare.) Then z = (U - mean(U)) /
   sqrt(var(U)), and for the one-sided question "is X larger?" p = 1 - Phi(z).
6. **Size of the excess - the Hodges-Lehmann estimator:** the median of all n*m
   differences (x - y). It's the rank-based answer to "how many milliseconds
   is hop k overstating?" With a few hundred samples per hop, computing all
   n*m differences is trivially cheap.

**Reading the result:**

| A (hop k vs. later hop) | p      | Meaning |
|-------------------------|--------|---------|
| clearly > 0.5 (>= ~0.7) | small  | Hop k is a slow responder. Gray it out and show its excess (the HL estimate) as "not real". |
| near 0.5                | large  | No evidence that hop k inflates. Its RTT is plausibly real. |
| clearly < 0.5           | small  | The normal case: delay builds up as you go further. |

**Which later hop?** Compare k against k+1, and also against the final
destination, which has the best-sampled distribution of all. If either
comparison shows an inversion, k's excess isn't real. Two tests per hop is a
multiple-comparisons issue; the simple, conservative fix is the Bonferroni
correction: require p < 0.05/2.

**A paired version.** Because probes rotate, a hop-k probe and a hop-k+1 probe
on the same flow are often sent within a second or two of each other. Pair
them up, take the differences d = x - y, and run the **Wilcoxon signed-rank
test** on the d's. Pairing cancels out whatever both probes had in common -
your Wi-Fi having a bad moment, say - which makes the test much more sensitive
for the same number of samples. If pairing is reliable enough in practice, it
should be the main test, with the unpaired version as a cross-check.

**Pitfalls:**

* **With enough data, everything is "significant".** Thousands of samples will
  make a 0.1 ms difference come out at p < 0.001. Always require a meaningful
  effect size (A, or an HL estimate of more than a millisecond or so) as well
  as a small p.
* **The samples aren't independent.** Congestion comes in episodes, so
  neighboring samples are correlated. That makes p-values look better than
  they are. Mitigations: thin the data (only use every Nth probe); or compute
  per-window medians (one-minute windows, say) and run the test on those, since
  fewer, more independent points give an honest p.
* **Return paths.** The Time Exceeded messages from k and from k+1 come back
  separately and may take different paths. A return-path difference can
  imitate an inversion, and nothing can correct for it. A large, persistent
  inversion is still almost always the slow path.
* **Rate limiting shows up as loss, not latency.** A router that only answers
  30% of probes, while later hops answer nearly all of theirs, is limiting
  ICMP generation; it is not dropping your traffic. Track each hop's response
  rate separately from loss, and never show non-answers at an intermediate hop
  as packet loss.
* **Silent hops.** Some routers never answer. Compare k with the next hop
  that does.

## Test 2: time correlation

**Principle:** real congestion changes over time - queues fill and drain - and
those changes carry through to everything downstream. If the link into hop k
is congested, then when hop k's RTT goes up, the endpoint's RTT should go up
too. Slow-path noise at k comes from k's CPU, not from the forwarding path, so
it should have no relation to what the endpoint sees.

**Building the data:** each hop-k probe is paired with the endpoint ping on
the same flow that was sent closest in time (pings go out every interval, so
there is always one within half an interval). That gives pairs (x_i, y_i):
hop-k RTT and endpoint RTT, measured at nearly the same moment.

**The test: Spearman's rank correlation, rho.** Rank the x's among themselves
and the y's among themselves, then compute the ordinary (Pearson) correlation
of the ranks:

    rho = 1 - 6 * sum(d_i^2) / (n(n^2 - 1))     (d_i = rank(x_i) - rank(y_i); exact when there are no ties)

rho near +1 means hop k and the endpoint rise and fall together; near 0 means
they're unrelated. Ranks make it insensitive to the occasional 2-second
outlier, which would swamp an ordinary correlation.

* Significance: t = rho * sqrt((n-2) / (1 - rho^2)), compared against Student's
  t distribution with n-2 degrees of freedom.
* Confidence interval: transform with z = atanh(rho). For Spearman's rho the
  standard error of z is about sqrt(1.06 / (n-3)) (Fieller, Hartley & Pearson,
  1957). Build the interval on z and transform back with tanh.

**The big confound: shared upstream delay.** Every hop's probes, and the
endpoint's pings, all pass through hop 1, which may well be your Wi-Fi. If the
Wi-Fi is jittery, *every* hop correlates with the endpoint, and the test
blames everything. The fix is a **partial correlation** controlling for an
upstream reference hop r (hop k-1, or the last hop before k that isn't a slow
responder):

    rho(k,end | r) = (rho_ke - rho_kr * rho_er) / sqrt((1 - rho_kr^2) * (1 - rho_er^2))

This asks: once you account for what hop r and the endpoint have in common,
does hop k still track the endpoint? If so, the time-varying delay was added
between r and k, and the link into k is where your traffic is getting held up.
(This needs probes to r, probes to k, and endpoint pings all close in time.
Rotation makes those triples sparser, which is one more reason to collect
plenty of data.)

**Pitfalls:**

* **No variation, no answer.** On a quiet path all RTTs are flat, rho is about
  0 everywhere, and that says nothing either way. Report "not enough variation
  to analyze", not "no congestion".
* **Route changes** mix two different situations together. Only analyze
  stretches of time in which the flow's path stayed the same.
* **Sample size.** To reliably detect a modest correlation (rho = 0.3, at 95%
  confidence with 80% power) you need about 85 pairs. Strong correlations
  (rho > 0.6) show up with 20-30.

## Putting the two together

| Downstream comparison     | Time correlation (partial) | Verdict |
|---------------------------|----------------------------|---------|
| k inflated vs. later hops | none                       | Slow responder. Ignore k's extra latency. |
| no inversion              | significant                | Real, varying congestion entering at k. This is the interesting one. |
| no inversion              | none                       | Hop is fine, or the path is too quiet to tell. |
| k inflated                | significant                | Both effects at once; or the return path is involved. Show the raw histograms and let a human judge. |

## The data budget

None of this is free. With one probe per ping, 1 ping/second, 4 flows and 12
hops, each (flow, hop) pair gets probed about once every 48 seconds. 30 samples
for one pair takes about 24 minutes. Flows that turn out to share a path pool
their samples, which helps a lot. Even so, the UI has to say "collecting..."
for a while before it can say anything, and it should always offer the raw
per-hop histogram (on mouseover), so the evidence is visible and not just the
verdict.

## Reading list

On the network side:
* RFC 792 - Internet Control Message Protocol. Defines what a Time Exceeded
  message quotes back: the IP header plus at least the first 8 bytes.
* RFC 1812 - Requirements for IP Version 4 Routers. Section 4.3.2.8 covers rate
  limiting of ICMP errors.
* Richard A. Steenbergen, "A Practical Guide to (Correctly) Troubleshooting
  with Traceroute", NANOG 45 (2009). The best single explanation of the slow
  path and how to read traceroute latency honestly.
* B. Augustin et al., "Avoiding traceroute anomalies with Paris traceroute",
  ACM IMC 2006. Flows, and keeping the checksum fixed.
* B. Augustin, T. Friedman, R. Teixeira, "Measuring Load-balanced Paths in the
  Internet", ACM IMC 2007.
* D. Veitch, B. Augustin, R. Teixeira, T. Friedman, "Failure Control in
  Multipath Route Tracing", IEEE INFOCOM 2009. The Multipath Detection
  Algorithm (MDA): how many flows to try at each hop before you can be
  confident you've found every next hop.

On the statistics side:
* H. B. Mann, D. R. Whitney, "On a Test of Whether one of Two Random Variables
  is Stochastically Larger than the Other", Annals of Mathematical Statistics,
  1947.
* F. Wilcoxon, "Individual Comparisons by Ranking Methods", Biometrics
  Bulletin, 1945. Both the rank-sum and the signed-rank tests.
* J. L. Hodges, E. L. Lehmann, "Estimates of Location Based on Rank Tests",
  Annals of Mathematical Statistics, 1963.
* C. Spearman, "The Proof and Measurement of Association between Two Things",
  American Journal of Psychology, 1904.
* E. C. Fieller, H. O. Hartley, E. S. Pearson, "Tests for Rank Correlation
  Coefficients. I", Biometrika, 1957. The standard error for Spearman's rho.
* M. Hollander, D. A. Wolfe, E. Chicken, *Nonparametric Statistical Methods*,
  3rd ed., Wiley, 2014. The textbook for everything above, including tie
  corrections and exact small-sample tables.
