#### About
this is naive implementantion of fastly-like ( https://www.fastly.com/blog/building-and-scaling-fastly-network-part-1-fighting-fib) 
daemon for monitoring neighbors (arp and ipv6 nd) addresses/state on arista's switches.
this is PoC, not a production-ready version. The client code right now just prints
msgs from daemon. But it's trivial to add more logic there (like actually adding
neighbors/ do some sanity checking/filtering etc).

#### Known issues
In SDK's version which were using during on_initialized phase neighbors_table_iterator was empty.
So we dont sync existing table to the daemon, only new events are propagated. Probably because it was 
EFT version and SDK's rpm was from a diff one.
