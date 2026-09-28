import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from backend.kafka_config import consumer_security
from backend.telemetry_service import KafkaBridge


class KafkaSecurityTests(unittest.TestCase):
    def options(self, **env):
        with patch.dict(os.environ, env, clear=True):
            return consumer_security()

    def test_production_defaults_to_verified_tls(self):
        options = self.options(SHADOWNET_ENV='production')
        self.assertEqual(options['security_protocol'], 'SSL')
        context = options['ssl_context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_plaintext_only_allowed_in_development(self):
        self.assertEqual(self.options(), {'security_protocol': 'PLAINTEXT'})
        with self.assertRaises(ValueError):
            self.options(SHADOWNET_ENV='production', SHADOWNET_KAFKA_SECURITY_PROTOCOL='PLAINTEXT')
        with self.assertRaises(ValueError):
            self.options(SHADOWNET_KAFKA_SECURITY_PROTOCOL='SASL_PLAINTEXT')

    def test_incomplete_or_ignored_credentials_are_rejected(self):
        cases = [
            {'SHADOWNET_KAFKA_CERT_FILE': '/missing/cert'},
            {'SHADOWNET_KAFKA_USERNAME': 'operator'},
            {'SHADOWNET_KAFKA_SECURITY_PROTOCOL': 'SASL_SSL'},
            {'SHADOWNET_KAFKA_SECURITY_PROTOCOL': 'SASL_SSL', 'SHADOWNET_KAFKA_SASL_MECHANISM': 'GSSAPI'},
            {'SHADOWNET_KAFKA_SECURITY_PROTOCOL': 'SSL', 'SHADOWNET_KAFKA_CA_FILE': '/missing/ca'},
        ]
        for env in cases:
            with self.subTest(env=env), self.assertRaises(ValueError):
                self.options(**env)

    def test_sasl_password_file_and_consumer_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / 'password'
            password_file.write_text('test-secret\n')
            env = {'SHADOWNET_ENV': 'production', 'SHADOWNET_KAFKA_SECURITY_PROTOCOL': 'SASL_SSL',
                   'SHADOWNET_KAFKA_USERNAME': 'operator', 'SHADOWNET_KAFKA_PASSWORD_FILE': str(password_file)}
            with patch.dict(os.environ, env, clear=True), patch('kafka.KafkaConsumer') as consumer:
                bridge = KafkaBridge(MagicMock(), 'broker:9093', 'events', 'group')
                options = consumer.call_args.kwargs
                self.assertEqual(options['sasl_mechanism'], 'SCRAM-SHA-512')
                self.assertEqual(options['sasl_plain_password'], 'test-secret')
                self.assertEqual(options['sasl_plain_username'], 'operator')
                self.assertTrue(options['ssl_context'].check_hostname)
                self.assertFalse(options['enable_auto_commit'])
                bridge.close()
            with self.assertRaises(ValueError):
                self.options(**env, SHADOWNET_KAFKA_PASSWORD='ambiguous')
            password_file.write_text('x' * 17000)
            with self.assertRaises(ValueError):
                self.options(**env)

    def test_mutual_tls_loads_explicit_certificate_pair(self):
        context = MagicMock()
        with patch('backend.kafka_config.ssl.create_default_context', return_value=context) as create:
            options = self.options(SHADOWNET_ENV='production', SHADOWNET_KAFKA_CA_FILE='/ca.pem',
                                   SHADOWNET_KAFKA_CERT_FILE='/client.pem', SHADOWNET_KAFKA_KEY_FILE='/key.pem')
        create.assert_called_once_with(cafile='/ca.pem')
        context.load_cert_chain.assert_called_once_with('/client.pem', '/key.pem')
        self.assertEqual(options['ssl_context'].verify_mode, ssl.CERT_REQUIRED)

    def test_bad_configuration_never_constructs_consumer(self):
        with patch.dict(os.environ, {'SHADOWNET_ENV': 'production', 'SHADOWNET_KAFKA_SECURITY_PROTOCOL': 'PLAINTEXT'}, clear=True), \
             patch('kafka.KafkaConsumer') as consumer:
            with self.assertRaises(ValueError):
                KafkaBridge(MagicMock(), 'broker:9092', 'events', 'group')
            consumer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
