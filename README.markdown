# EdgeDNS
EdgeDNS is a DNS reverse proxy written in Erlang that mitigates DNS Amplification attacks using a dampening
technique inspired by [Lutz Donnerhacke](http://lutz.donnerhacke.de/eng/Blog/DNS-Dampening).

# Installation
Basic installation instructions for unix systems here.

# Basic Configuration
Erlangs native configuration format can be quite a drag, especially for non-erlangers.
Therefore a YAML formatted configuration file can used with EdgeDNS instead. 
It is possible to omit the YAML config and configure EdgeDNS using the classical way
with rebar3 and semi-readable erlang-terms. See the section below for details.

An example configuration file is supplied [here](/config/edgedns_config_example.yml)
which includes descriptions of each option. When EdgeDNS i started it searches for a
configuration file named `edgedns_config.yml` in the following places (and order):

1. `./`
2. `~/.edgedns`
3. `/usr/local/etc`
4. `/etc`

When a file is found it stops searching.
Both filename and the list of places to search can be configured as well, as explained in 
the section below.

# Advanced Configuration (for Erlangers)
Configuration instructions for Erlangers here.
