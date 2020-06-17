Domain-TLD
==========

This package is a Bro script library that give Bro users the ability to efficiently 
discover if a given domain name is effectively a TLD. It was created to help
Bro developers easily discover if domains like `google.uk.co` are effectively TLDs. 
It avoids the trouble of splitting on periods and making the incorrect assumption
that `uk` is the interesting component of the name. It also has functionality to 
extract the domain from the FQDN.

Installation
------------

::

	bro-pkg install sethhall/domain-tld

API
---

For now, refer to the inline documentation in the `scripts/main.bro` script.
