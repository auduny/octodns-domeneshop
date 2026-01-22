#
#
#

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'


import logging
from collections import defaultdict

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record


class DomeneshopClientException(ProviderException):
    pass


class DomeneshopClientNotFound(DomeneshopClientException):
    def __init__(self):
        super().__init__('Not Found')


class DomeneshopClientUnauthorized(DomeneshopClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class DomeneshopClient:
    """
    A client for the Domeneshop API.
    
    Uses the API documented at https://api.domeneshop.no/docs/
    """

    def __init__(self, token, secret):
        self._token = token
        self._secret = secret
        sess = Session()
        sess.auth = (token, secret)
        sess.headers.update(
            {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': f'octodns/{octodns_version} octodns-domeneshop/{__VERSION__}',
            }
        )
        self._sess = sess
        self.base = 'https://api.domeneshop.no/v0'

    def _request(self, method, path, params=None, data=None):
        url = f'{self.base}{path}'
        resp = self._sess.request(method, url, params=params, json=data)
        if resp.status_code == 401:
            raise DomeneshopClientUnauthorized()
        if resp.status_code == 404:
            raise DomeneshopClientNotFound()
        resp.raise_for_status()
        return resp

    def domains(self):
        """List all domains"""
        return self._request('GET', '/domains').json()

    def domain(self, domain_id):
        """Get a specific domain by ID"""
        return self._request('GET', f'/domains/{domain_id}').json()

    def domain_id_for_name(self, domain_name):
        """
        Find the domain ID for a given domain name.
        
        :param domain_name: Domain name without trailing dot (e.g., 'example.com')
        :return: Domain ID
        :raises DomeneshopClientNotFound: If domain is not found
        """
        domains = self.domains()
        for domain in domains:
            if domain['domain'] == domain_name:
                return domain['id']
        raise DomeneshopClientNotFound()

    def records(self, domain_id):
        """List all DNS records for a domain"""
        return self._request('GET', f'/domains/{domain_id}/dns').json()

    def record_create(self, domain_id, record):
        """Create a DNS record for a domain"""
        resp = self._request('POST', f'/domains/{domain_id}/dns', data=record)
        # The API returns the record ID in the Location header
        location = resp.headers.get('Location', '')
        if location:
            record_id = location.split('/')[-1]
            return int(record_id)
        return None

    def record_update(self, domain_id, record_id, record):
        """Update a DNS record"""
        self._request('PUT', f'/domains/{domain_id}/dns/{record_id}', data=record)

    def record_delete(self, domain_id, record_id):
        """Delete a DNS record"""
        self._request('DELETE', f'/domains/{domain_id}/dns/{record_id}')

    def forwards(self, domain_id):
        """List all HTTP forwards for a domain"""
        return self._request('GET', f'/domains/{domain_id}/forwards/').json()

    def forward_create(self, domain_id, forward):
        """Create an HTTP forward for a domain"""
        self._request('POST', f'/domains/{domain_id}/forwards/', data=forward)

    def forward_update(self, domain_id, host, forward):
        """Update an HTTP forward"""
        self._request('PUT', f'/domains/{domain_id}/forwards/{host}', data=forward)

    def forward_delete(self, domain_id, host):
        """Delete an HTTP forward"""
        self._request('DELETE', f'/domains/{domain_id}/forwards/{host}')

    def nameservers_update(self, domain_id, nameservers):
        """Update nameservers for a domain"""
        self._request('PUT', f'/domains/{domain_id}', data={'nameservers': nameservers})


class DomeneshopProvider(BaseProvider):
    """
    Domeneshop DNS provider for octoDNS.
    
    domeneshop:
        class: octodns_domeneshop.DomeneshopProvider
        # API token (required)
        token: env/DOMENESHOP_TOKEN
        # API secret (required)
        secret: env/DOMENESHOP_SECRET
    """

    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'DS',
            'MX',
            'NS',
            'SRV',
            'TLSA',
            'TXT',
            'URLFWD',
        )
    )

    def __init__(self, id, token, secret, include_nameservers=False, *args, **kwargs):
        self.log = logging.getLogger(f'DomeneshopProvider[{id}]')
        self.log.debug('__init__: id=%s, token=***, secret=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = DomeneshopClient(token, secret)
        # When enabled, emit domain nameservers as root NS records during populate/dump
        self._include_nameservers = include_nameservers

        self._zone_records = {}
        self._domain_ids = {}
        self._zone_forwards = {}
        self._zone_nameservers = {}

    def _get_domain_id(self, zone_name):
        """
        Get the domain ID for a zone name, caching the result.
        
        :param zone_name: Zone name with trailing dot (e.g., 'example.com.')
        :return: Domain ID
        """
        if zone_name not in self._domain_ids:
            # Remove trailing dot for API call
            domain_name = zone_name[:-1]
            self._domain_ids[zone_name] = self._client.domain_id_for_name(
                domain_name
            )
        return self._domain_ids[zone_name]

    def _data_for_multiple(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [r['data'] for r in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple

    def _data_for_NS(self, _type, records):
        values = []
        for record in records:
            value = record['data']
            # Ensure trailing dot
            if not value.endswith('.'):
                value = f'{value}.'
            values.append(value)
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_TXT(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            # escape semicolons
            'values': [r['data'].replace(';', '\\;') for r in records],
        }

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'flags': record['flags'],
                    'tag': record['tag'],
                    'value': record['data'],
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        value = record['data']
        # Ensure trailing dot
        if not value.endswith('.'):
            value = f'{value}.'
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': value,
        }

    _data_for_ALIAS = _data_for_CNAME

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            value = record['data']
            # Ensure trailing dot
            if not value.endswith('.'):
                value = f'{value}.'
            values.append(
                {
                    'preference': record['priority'],
                    'exchange': value,
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
            target = record['data']
            # Ensure trailing dot
            if not target.endswith('.'):
                target = f'{target}.'
            values.append(
                {
                    'port': record['port'],
                    'priority': record['priority'],
                    'target': target,
                    'weight': record['weight'],
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_DS(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'key_tag': record['tag'],
                    'algorithm': record['alg'],
                    'digest_type': record['digest'],
                    'digest': record['data'],
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_TLSA(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'certificate_usage': record['usage'],
                    'selector': record['selector'],
                    'matching_type': record['dtype'],
                    'certificate_association_data': record['data'],
                }
            )
        return {'type': _type, 'ttl': records[0]['ttl'], 'values': values}

    def _data_for_URLFWD(self, _type, forwards):
        values = []
        for forward in forwards:
            values.append(
                {
                    # Domeneshop forwards do not expose TTLs; use a sensible default
                    'path': '/',
                    'target': forward['url'],
                    'code': 301,
                    'masking': 0,
                    'query': 1,
                }
            )
        return {'type': _type, 'ttl': 3600, 'values': values}

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                domain_id = self._get_domain_id(zone.name)
                self._zone_records[zone.name] = self._client.records(domain_id)
            except DomeneshopClientNotFound:
                return []

        return self._zone_records[zone.name]

    def zone_forwards(self, zone):
        if zone.name not in self._zone_forwards:
            try:
                domain_id = self._get_domain_id(zone.name)
                self._zone_forwards[zone.name] = self._client.forwards(domain_id)
            except DomeneshopClientNotFound:
                return []

        return self._zone_forwards[zone.name]

    def zone_nameservers(self, zone):
        if zone.name not in self._zone_nameservers:
            try:
                domain_id = self._get_domain_id(zone.name)
                domain = self._client.domain(domain_id)
                self._zone_nameservers[zone.name] = domain.get('nameservers', [])
            except DomeneshopClientNotFound:
                return []

        return self._zone_nameservers[zone.name]

    def list_zones(self):
        return [f'{d["domain"]}.' for d in self._client.domains()]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        
        # Get records for the zone
        records_list = self.zone_records(zone)
        for record in records_list:
            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            # Domeneshop uses @ for the root, octodns uses empty string
            host = record['host']
            if host == '@':
                host = ''
            values[host][record['type']].append(record)

        # Try to get forwards and registrar nameservers even when there are no DNS records
        forwards = defaultdict(list)
        for forward in self.zone_forwards(zone):
            host = forward['host']
            if host == '@':
                host = ''
            if not forward['frame']:
                forwards[host].append(forward)

        if forwards:
            for host, forward_list in forwards.items():
                values[host]['URLFWD'].extend(forward_list)

        # Optionally include registrar nameservers as root NS records for dumps
        if self._include_nameservers:
            nameservers = self.zone_nameservers(zone)
            if nameservers and ('NS' not in values['']):
                ns_records = [
                    {'host': '@', 'ttl': 3600, 'data': ns} for ns in nameservers
                ]
                values['']['NS'].extend(ns_records)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                # Skip if records list is empty
                if not records:
                    continue
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _params_for_multiple(self, record):
        for value in record.values:
            # Domeneshop uses @ for the root
            host = record.name if record.name else '@'
            yield {
                'data': value,
                'host': host,
                'ttl': record.ttl,
                'type': record._type,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple

    def _params_for_TXT(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            yield {
                # un-escape semicolons
                'data': value.replace('\\;', ';'),
                'host': host,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_CAA(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            yield {
                'data': value.value,
                'flags': value.flags,
                'host': host,
                'tag': value.tag,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_single(self, record):
        host = record.name if record.name else '@'
        # Remove trailing dot for API
        value = record.value
        if value.endswith('.'):
            value = value[:-1]
        yield {
            'data': value,
            'host': host,
            'ttl': record.ttl,
            'type': record._type,
        }

    _params_for_ALIAS = _params_for_single
    _params_for_CNAME = _params_for_single

    def _params_for_MX(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            # Remove trailing dot for API
            exchange = value.exchange
            if exchange.endswith('.'):
                exchange = exchange[:-1]
            yield {
                'data': exchange,
                'host': host,
                'priority': value.preference,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_SRV(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            # Remove trailing dot for API
            target = value.target
            if target.endswith('.'):
                target = target[:-1]
            yield {
                'data': target,
                'host': host,
                'port': value.port,
                'priority': value.priority,
                'ttl': record.ttl,
                'type': record._type,
                'weight': value.weight,
            }

    def _params_for_DS(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            yield {
                'alg': value.algorithm,
                'data': value.digest,
                'digest': value.digest_type,
                'host': host,
                'tag': value.key_tag,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_TLSA(self, record):
        for value in record.values:
            host = record.name if record.name else '@'
            yield {
                'data': value.certificate_association_data,
                'dtype': value.matching_type,
                'host': host,
                'selector': value.selector,
                'ttl': record.ttl,
                'type': record._type,
                'usage': value.certificate_usage,
            }

    def _params_for_URLFWD(self, record):
        host = record.name if record.name else '@'
        for value in record.values:
            yield {
                'host': host,
                'url': value.target,
                'frame': False,
            }

    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        domain_id = self._get_domain_id(new.zone.name)

        if new._type == 'URLFWD':
            # Create HTTP forwards
            for params in params_for(new):
                self._client.forward_create(domain_id, params)
        elif new._type == 'NS' and new.name == '':
            # Update root nameservers
            nameservers = [v.rstrip('.') for v in new.values]
            self._client.nameservers_update(domain_id, nameservers)
        else:
            # Create DNS records
            for params in params_for(new):
                self._client.record_create(domain_id, params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        domain_id = self._get_domain_id(zone.name)
        # Domeneshop uses @ for the root
        target_host = existing.name if existing.name else '@'

        if existing._type == 'URLFWD':
            # Delete HTTP forwards
            for forward in self.zone_forwards(zone):
                if target_host == forward['host']:
                    self._client.forward_delete(domain_id, forward['host'])
        elif existing._type == 'NS' and existing.name == '':
            # For root NS records, we need to update nameservers
            # This is typically not allowed to be deleted, only updated
            # So we skip deletion for root NS records
            pass
        else:
            # Delete DNS records
            for record in self.zone_records(zone):
                if (
                    target_host == record['host']
                    and existing._type == record['type']
                ):
                    self._client.record_delete(domain_id, record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # Clear out the caches if any
        self._zone_records.pop(desired.name, None)
        self._zone_forwards.pop(desired.name, None)
        self._zone_nameservers.pop(desired.name, None)
