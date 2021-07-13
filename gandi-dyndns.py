#!/usr/bin/python3

import re
import sys
import requests

from optparse import OptionParser

GANDI_API = 'https://api.gandi.net/v5/'

def api_request(apikey, endpoint, payload=None):
    if payload is not None:
        result = requests.put(GANDI_API + endpoint, json=payload, headers={"Authorization": "Apikey " + apikey})
    else:
        result = requests.get(GANDI_API + endpoint, headers={"Authorization": "Apikey " + apikey})
    result.raise_for_status()
    return result.json()

def list_domains(apikey):
    return api_request(apikey, 'livedns/domains')

def get_record(apikey, domain, name, rtype):
    return api_request(apikey, 'livedns/domains/' + domain + '/records/' + name + '/' + rtype)

def update_record(apikey, domain, name, rtype, payload):
    return api_request(apikey, 'livedns/domains/' + domain + '/records/' + name + '/' + rtype, payload)

def get_public_ipv4():
    result = requests.get('https://ipv4.icanhazip.com/')
    result.raise_for_status()
    matchip = re.search('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.text)
    if matchip:
        return matchip.group(1)
    return None

def get_public_ipv6():
    result = requests.get('https://ipv6.icanhazip.com/')
    result.raise_for_status()
    matchip = re.search('([0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)', result.text)
    if matchip:
        return matchip.group(1)
    return None

def usage():
    print('Usage: gandi-dyndns --api=<APIKEY> --domain=<DOMAIN> --record=<RECORD> [--ipv4] [--ipv6] [--quiet]')
    print('Example: gandi-dyndns --api=123ApIkEyFrOmGanDi --domain=example.com --record=www --ipv4')

def main():
    apikey = ''
    domain = ''
    record = ''
    rtypes = []
    quiet=False

    optp = OptionParser()
    optp.add_option('-a', '--apikey', help='Specify API key')
    optp.add_option('-d', '--domain', help='Specify domain')
    optp.add_option('-4', '--ipv4', help='Enable IPv4', action='store_true')
    optp.add_option('-6', '--ipv6', help='Enable IPv6', action='store_true')
    optp.add_option('-r', '--record', help='Specify record data')
    optp.add_option('--extip4', help='Force external IPv4. This can be used to update a record with an IP different than the IP of the server/workstation from which the script is executed')
    optp.add_option('--extip6', help='Force external IPv6. This can be used to update a record with an IP different than the IP of the server/workstation from which the script is executed')
    optp.add_option('-q', '--quiet', help='No output except to stderr on error', action='store_true')
    (opts, args) = optp.parse_args()

    # Process Arguments
    if opts.ipv4: rtypes.append('A')
    if opts.ipv6: rtypes.append('AAAA')
    domain = opts.domain
    apikey = opts.apikey
    record = opts.record
    extip4 = opts.extip4
    extip6 = opts.extip6
    if opts.quiet: quiet=True
    if not rtypes: rtypes = ['A']

    if apikey == None or apikey == '':
        print('No Apikey specified', file=sys.stderr)
        usage()
        sys.exit(79)

    if domain == None:
        print('No Domain specified', file=sys.stderr)
        usage()
        sys.exit(81)

    try:
        domain_list = list_domains(apikey)
    except requests.exceptions.HTTPError as err:
        print('Failed to validate API key: ' + str(err))
        usage()
        sys.exit(80)

    domain_found = False
    for item in domain_list:
        if 'fqdn' in item and item['fqdn'] == domain:
            domain_found = True
            break

    if not domain_found:
        print('Domain ' + domain + ' does not exist on provided API account', file=sys.stderr)
        usage()
        sys.exit(82)

    for rtype in rtypes:
        if rtype == 'A':
            public_ip = get_public_ipv4()
        if rtype == 'AAAA':
            public_ip = get_public_ipv6()
        if not public_ip:
            print('Failed to determine public IP address of type ' + rtype, file=sys.stderr)
            sys.exit(84)

        try:
            record_data = get_record(apikey, domain, record, rtype)
        except requests.exceptions.HTTPError as err:
            print('Failed to retrieve ' + rtype + ' record "' + record + '" for domain "' + domain + '": ' + str(err), file=sys.stderr)
            usage()
            sys.exit(83)

        if public_ip in record_data['rrset_values']:
            if not quiet:
                print('The public IP address for ' + record + ' record did not change: ' + public_ip)
        else:
            if not quiet:
                print('Updating "' + record + '" ' + rtype + ' record: ' + record_data['rrset_values'][0] + ' -> ' + public_ip)
            record_data['rrset_values'] = [ public_ip ]
            try:
                update_record(apikey, domain, record, rtype, record_data)
            except requests.exceptions.HTTPError as err:
                print('Failed to update record of type ' + rtype + ': ' + str(err), file=sys.stderr)
                sys.exit(85)

if __name__ == "__main__":
    main()

