# Gandi Dyndns v5

Automatically update your IPv4 and/or IPv6 DNS records using [Gandi](https://www.gandi.net/)'s [LiveDNS](https://api.gandi.net/docs/livedns/) API.

This project is a fork of https://github.com/lembregtse/gandi-dyndns mostly rewritten to work with Python 3 and the newer API v5 instead of API v4. Public IP is retrieved through [icanhaz](https://github.com/major/icanhaz).

The development of this tool or myself are in no way involved with Gandi.net

# Requirements

Everything should come with a default Python setup:

* Python 3
* re
* sys
* requests
* optparse

# API Key

Generate your API key from Gandi's [API Key Page](https://www.gandi.net/admin/api_key) in the Security section.

# Usage

```
Usage: gandi-dyndns --api=<APIKEY> --domain=<DOMAIN> --record=<RECORD> [--ipv4] [--ipv6] [--quiet]
Example: gandi-dyndns --api=123ApIkEyFrOmGanDi --domain=example.com --record=www --ipv4
```