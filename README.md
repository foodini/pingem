# pingem
This is a minor side project that is intended to replace the bash_environment's
pingstats with something of greater visual bandwidth, as well as being 
decoupled from the platform. (pingstats only works in iTerm and triggers a bug
in iTerm that has existed for years and shows no signs of ever being fixed.)

The intent is to fire up pingem with a couple endpoints, and a ping will be
started to those endpoints. Statistics on rtt, like avg and a bunch of 
percentiles, as well as info about loss will be displayed and updated in real
time.

One of the things that I'm discovering is that my personal habits for
identifiers clash with those of javascript. In general, there's no strong
technical argument to be made for choosing CamelCasing vs dromedaryCasing vs
my_preferred_style, but on can argue that javascript adds a potential objective
argument: bandwidth. This project is uncacheable and the javascript is fully
"downloaded" every time. The extra underscores are bytes squandered, but I don't
give a crap. This is not intended to work across the network. It's all
localhost.

I tried, briefly, sticking to JS style in JS and python style in python, but I
found my on-the-wire identifiers clashing so I said fuckit. Anything you see
that isn't underscored is v0.0.0.01 stuff that has lingered.
