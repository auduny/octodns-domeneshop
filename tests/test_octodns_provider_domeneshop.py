#
#
#

from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_domeneshop import (
    DomeneshopClient,
    DomeneshopClientNotFound,
    DomeneshopClientUnauthorized,
    DomeneshopProvider,
)


class TestDomeneshopProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(expected)

    def test_list_zones(self):
        provider = DomeneshopProvider('test', 'token', 'secret')

        with requests_mock() as mock:
            mock.get(
                'https://api.domeneshop.no/v0/domains',
                json=[
                    {'id': 1, 'domain': 'first.com'},
                    {'id': 2, 'domain': 'second.com'},
                ],
            )

            zones = provider.list_zones()
            self.assertEqual(['first.com.', 'second.com.'], zones)

    def test_populate(self):
        provider = DomeneshopProvider('test', 'token', 'secret')

        # Bad auth
        with requests_mock() as mock:
            mock.get(ANY, status_code=401, text='{"message": "Unauthorized"}')

            with self.assertRaises(Exception) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual('Unauthorized', str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text='Things caught fire')

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone('unit.tests.', [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            # First call is to get domain list
            mock.get(
                'https://api.domeneshop.no/v0/domains',
                json=[{'id': 1, 'domain': 'other.tests'}],
            )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(set(), zone.records)

        # Reset provider to clear cache
        provider = DomeneshopProvider('test', 'token', 'secret')

        # Successfully populate zone
        with requests_mock() as mock:
            mock.get(
                'https://api.domeneshop.no/v0/domains',
                json=[
                    {'id': 1, 'domain': 'unit.tests'},
                    {'id': 2, 'domain': 'other.tests'},
                ],
            )
            with open('tests/fixtures/domeneshop-records.json') as fh:
                mock.get(
                    'https://api.domeneshop.no/v0/domains/1/dns',
                    text=fh.read(),
                )

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(8, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(0, len(changes))

        # 2nd populate makes no network calls/all from cache
        again = Zone('unit.tests.', [])
        provider.populate(again)
        self.assertEqual(8, len(again.records))

    def test_apply(self):
        provider = DomeneshopProvider('test', 'token', 'secret', strict_supports=False)

        resp = Mock()
        resp.json = Mock()
        resp.headers = {'Location': '/v0/domains/1/dns/100'}
        provider._client._request = Mock(return_value=resp)

        # Set up the zone records cache for deletes to work
        provider._zone_records['unit.tests.'] = []
        provider._domain_ids['unit.tests.'] = 1

        # non-existent domain records
        resp.json.side_effect = [
            [],  # empty records for populate
        ]
        plan = provider.plan(self.expected)

        # All records should be created
        n = len(self.expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))

        # Verify that record_create was called for each record
        create_calls = [
            c for c in provider._client._request.call_args_list
            if c[0][0] == 'POST'
        ]
        self.assertTrue(len(create_calls) > 0)

        provider._client._request.reset_mock()

        # Test delete and update
        provider._client.records = Mock(
            return_value=[
                {
                    'id': 11189897,
                    'host': 'www',
                    'data': '1.2.3.4',
                    'ttl': 300,
                    'type': 'A',
                },
                {
                    'id': 11189898,
                    'host': 'www',
                    'data': '2.2.3.4',
                    'ttl': 300,
                    'type': 'A',
                },
                {
                    'id': 11189899,
                    'host': 'ttl',
                    'data': '3.2.3.4',
                    'ttl': 600,
                    'type': 'A',
                },
            ]
        )
        # Set up cache
        provider._zone_records['unit.tests.'] = [
            {
                'id': 11189897,
                'host': 'www',
                'data': '1.2.3.4',
                'ttl': 300,
                'type': 'A',
            },
            {
                'id': 11189898,
                'host': 'www',
                'data': '2.2.3.4',
                'ttl': 300,
                'type': 'A',
            },
            {
                'id': 11189899,
                'host': 'ttl',
                'data': '3.2.3.4',
                'ttl': 600,
                'type': 'A',
            },
        ]

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted, 'ttl', {'ttl': 300, 'type': 'A', 'value': '3.2.3.4'}
            )
        )

        plan = provider.plan(wanted)
        self.assertTrue(plan.exists)
        self.assertEqual(2, len(plan.changes))
        self.assertEqual(2, provider.apply(plan))

        # Verify delete calls for www records and update for ttl
        delete_calls = [
            c for c in provider._client._request.call_args_list
            if c[0][0] == 'DELETE'
        ]
        self.assertTrue(len(delete_calls) >= 2)


class TestDomeneshopClient(TestCase):
    def test_client_request_unauthorized(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.get(ANY, status_code=401)

            with self.assertRaises(DomeneshopClientUnauthorized):
                client.domains()

    def test_client_request_not_found(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.get(ANY, status_code=404)

            with self.assertRaises(DomeneshopClientNotFound):
                client.domains()

    def test_client_domains(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.get(
                'https://api.domeneshop.no/v0/domains',
                json=[
                    {'id': 1, 'domain': 'example.com'},
                    {'id': 2, 'domain': 'example.org'},
                ],
            )

            domains = client.domains()
            self.assertEqual(2, len(domains))
            self.assertEqual('example.com', domains[0]['domain'])

    def test_client_domain_id_for_name(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.get(
                'https://api.domeneshop.no/v0/domains',
                json=[
                    {'id': 1, 'domain': 'example.com'},
                    {'id': 2, 'domain': 'example.org'},
                ],
            )

            domain_id = client.domain_id_for_name('example.org')
            self.assertEqual(2, domain_id)

            # Domain not found
            with self.assertRaises(DomeneshopClientNotFound):
                client.domain_id_for_name('notfound.com')

    def test_client_records(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.get(
                'https://api.domeneshop.no/v0/domains/1/dns',
                json=[
                    {'id': 1, 'host': '@', 'type': 'A', 'data': '1.2.3.4', 'ttl': 300},
                ],
            )

            records = client.records(1)
            self.assertEqual(1, len(records))
            self.assertEqual('A', records[0]['type'])

    def test_client_record_create(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.post(
                'https://api.domeneshop.no/v0/domains/1/dns',
                status_code=201,
                headers={'Location': '/v0/domains/1/dns/123'},
            )

            record_id = client.record_create(
                1, {'host': '@', 'type': 'A', 'data': '1.2.3.4', 'ttl': 300}
            )
            self.assertEqual(123, record_id)

    def test_client_record_delete(self):
        client = DomeneshopClient('token', 'secret')

        with requests_mock() as mock:
            mock.delete(
                'https://api.domeneshop.no/v0/domains/1/dns/123',
                status_code=204,
            )

            # Should not raise
            client.record_delete(1, 123)
