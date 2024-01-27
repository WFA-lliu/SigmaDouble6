# SigmaDouble6
---

## Usage:

```sh
usage: sigmadouble.py [-h] [-v] [-f filename] [-i mapped_ipv4]
                      [-p mapped_port_base]
                      [-s mapping_stored_filename | -l mapping_loaded_filename]

CLI argument parsing

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbosity
  -f filename, --filename filename
                        filename of UCC log
  -i mapped_ipv4, --ip mapped_ipv4
                        mapped IPv4 address; only for mapping stored filename
  -p mapped_port_base, --port mapped_port_base
                        mapped TCP listening port base; only for mapping
                        stored filename
  -s mapping_stored_filename, --store mapping_stored_filename
                        mapping stored filename, from UCC log; YAML formatted
  -l mapping_loaded_filename, --load mapping_loaded_filename
                        mapping loaded filename, to UCC log; YAML formatted
```

## Description:
A test double to **emulate** Sigma handshaking based on existing log.
This design is for the condition that Sigma instances such as DUT and/or sniffer are unavailable.

A Sigma instance follows the **WTS CAPI specification** to receive and send formatted strings over a TCP socket; UCC core sends CAPI request to a Sigma instance, and the Sigma instance sends CAPI response to UCC core accordingly.

This test double is designed to replace Sigma instances by a few socket servers; the socket client, i.e. UCC core, switches its connection with those socket servers (instead of actual Sigma instances). All the CAPI request/response patterns are retrieved from existing UCC log.
This test double would:
> parse the specified UCC log,
> gather every Sigma instances,
> gather request/response from each Sigma instances, and
> spawn TCP socket servers with request/response collection accordingly.

The UCC core must alter:
> initialization configuration, i.e. AllInitConfig_\*.txt file in cmds/WTS-\* directory, with the IP and port setting from this test double.
> > Notice here, when DUT is one of testbeds, the handle (IP-port pair) of the testbed is recommended to be commented/removed.

Thus, when UCC core sends request to test double, then, test double will send corresponding response back; **just like replaying the tapes of music**.
