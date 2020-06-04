# vyger

Quick and easy CVE scanning for Linux systems

vyger is a standalone utility that can be downloaded and run on a Linux system to scan for any unapplied CVEs on the system it is run on.
It is release under the LGPLv3 license that allows for free usage and inclusion in propreitary systems, but any changes to vyger code
must be made available.

Supported system families:

  - Ubuntu
  - Debian (planned)
  - Alpine (planned)

# usage

Since vyger is distributed as one module it can be fetched and run directly to the target system.

```sh
curl -sS https://raw.githubusercontent.com/mrodden/vyger/master/cve.py | python3
```
