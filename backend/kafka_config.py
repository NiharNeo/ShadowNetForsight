"""Deployment-owned Kafka transport configuration; never accepted from HTTP clients."""
from __future__ import annotations

import os
from pathlib import Path
import ssl


def consumer_security() -> dict:
    production = os.getenv('SHADOWNET_ENV') == 'production'
    protocol = os.getenv('SHADOWNET_KAFKA_SECURITY_PROTOCOL', 'SSL' if production else 'PLAINTEXT')
    if protocol not in {'PLAINTEXT', 'SSL', 'SASL_SSL'}:
        raise ValueError('Kafka security protocol must be PLAINTEXT, SSL or SASL_SSL')
    if production and protocol == 'PLAINTEXT':
        raise ValueError('Production Kafka requires SSL or SASL_SSL')
    ca = os.getenv('SHADOWNET_KAFKA_CA_FILE') or None
    cert = os.getenv('SHADOWNET_KAFKA_CERT_FILE') or None
    key = os.getenv('SHADOWNET_KAFKA_KEY_FILE') or None
    username = os.getenv('SHADOWNET_KAFKA_USERNAME') or None
    password = os.getenv('SHADOWNET_KAFKA_PASSWORD') or None
    password_file = os.getenv('SHADOWNET_KAFKA_PASSWORD_FILE') or None
    mechanism = os.getenv('SHADOWNET_KAFKA_SASL_MECHANISM') or None
    if protocol != 'SASL_SSL' and any((username, password, password_file, mechanism)):
        raise ValueError('Kafka SASL settings require SASL_SSL')
    if protocol == 'PLAINTEXT' and any((ca, cert, key)):
        raise ValueError('Kafka TLS settings require a TLS protocol')
    if bool(cert) != bool(key):
        raise ValueError('Kafka client certificate and key must be configured together')
    result = {'security_protocol': protocol}
    if protocol != 'PLAINTEXT':
        try:
            context = ssl.create_default_context(cafile=ca)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            if cert:
                context.load_cert_chain(cert, key)
        except (OSError, ssl.SSLError) as error:
            raise ValueError('Kafka TLS certificate configuration is invalid or unreadable') from error
        result['ssl_context'] = context
    if protocol == 'SASL_SSL':
        mechanism = mechanism or 'SCRAM-SHA-512'
        if mechanism not in {'SCRAM-SHA-256', 'SCRAM-SHA-512', 'PLAIN'}:
            raise ValueError('Unsupported Kafka SASL mechanism')
        if password and password_file:
            raise ValueError('Set one Kafka password source only')
        if password_file:
            try:
                with Path(password_file).open('r', encoding='utf-8') as stream:
                    password = stream.read(16385).rstrip('\r\n')
            except (OSError, UnicodeError) as error:
                raise ValueError('Kafka password file is unreadable') from error
        if not username or not password or len(password) > 16384:
            raise ValueError('Kafka SASL requires a username and a non-empty password of at most 16384 characters')
        result.update(sasl_mechanism=mechanism, sasl_plain_username=username, sasl_plain_password=password)
    return result
