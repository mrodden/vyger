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

Since vyger is distributed as a single Python3 module with only standard library dependencies, it can be fetched to and run directly on the target system.

```sh
curl -sS https://raw.githubusercontent.com/mrodden/vyger/master/cve.py | python3
```

If you have unapplied CVEs, you will get output on what CVEs and which packages. Below is some sample output from an Ubuntu 18.04 LTS machine with the base openssl package:
```sh
$ python3 cve.py
CVE-2018-0734 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.3 or later
CVE-2018-0735 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.3 or later
CVE-2018-5407 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.3 or later
CVE-2019-1547 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.1-1ubuntu2.1~18.04.6 or later
CVE-2019-1549 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.1-1ubuntu2.1~18.04.6 or later
CVE-2019-1551 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.1-1ubuntu2.1~18.04.6 or later
CVE-2019-1559 on Ubuntu 18.04 LTS (bionic) - medium. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.3 or later
CVE-2019-1563 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.1-1ubuntu2.1~18.04.6 or later
CVE-2018-0495 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.1 or later
CVE-2018-0732 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.1 or later
CVE-2018-0737 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.0g-2ubuntu4.1 or later
CVE-2019-1543 on Ubuntu 18.04 LTS (bionic) - low. Alert: 'openssl' is at 1.1.0g-2ubuntu4, need 1.1.1-1ubuntu2.1~18.04.2 or later
```

In this case we would want to grab the latest openssl package available and re-run the tool:
```sh
# grab the latest openssl updates
$ sudo apt-get install -y openssl
...

# no output because now we have all fixes currently available on this 18.04 LTS host
$ python3 cve.py
$
```
