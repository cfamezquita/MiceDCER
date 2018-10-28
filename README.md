# MiceDCER
An Efficient Mice Flow Routing Algorithm for Mice Flows in SDN-based Data Centers.

It aims to reduce the delay on mice flows by reducing the number of rules on switching tables. It is done by installing wildcard rules and assigning PMACs to the edge switches.

It is written in Python for Ryu framework, for use with OpenFlow 1.3.
It has been tested in virtual _k_-ary FatTree topology with Ryu 4.23 and Mininet 2.2.2.

This repository also includes Chadi Assi's presentation of the algorithm.

## Changelog:
* **Alpha Version 3 - 2018.10.28**
  * Fix ARP stormflood bug by dropping the ARP packets on core and aggregate switches instead of flooding them.
  * Controller now generates requests on edge switches when receiving an ARP request.

* **Alpha Version 2 - 2018.10.25**
  * Fix a lot of bugs from initial version

* **Alpha Version 1 - 2018.10.15**
  * Initial Version
