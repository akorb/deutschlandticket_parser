import hashlib
from datetime import datetime
from pathlib import Path

CERTS_DIR = Path(__file__).parent / 'certs'
RSA_OID = bytes.fromhex('2b240304020201')
MODULUS_SIZES = {3: 192, 4: 128}  # by certificate profile identifier
SHA1_SIZE = 20


class ByteStringTaker:
    __slots__ = ['unprocessed_data']

    def __init__(self, byte_str: bytes):
        self.unprocessed_data = byte_str

    def take(self, n):
        chunk = self.unprocessed_data[:n]
        self.unprocessed_data = self.unprocessed_data[n:]
        return chunk

    def take_int(self, n):
        return int.from_bytes(self.take(n), 'big')

    def take_length(self):
        length = self.take(1)[0]
        return self.take(1)[0] if length == 0x81 else length

    def completely_processed(self):
        return len(self.unprocessed_data) == 0


class RsaKey:
    def __init__(self, certificate_content: bytes):
        content = ByteStringTaker(certificate_content)
        profile = content.take(1)[0]
        content.take(31)  # CAR, CHR, CHA and end of validity
        oid = content.take(len(RSA_OID))
        assert (oid == RSA_OID)
        self.modulus = content.take_int(MODULUS_SIZES[profile])
        self.exponent = content.take_int(4)

        assert (content.completely_processed())


def load_ca_key(car: bytes) -> RsaKey:
    certificate = ByteStringTaker((CERTS_DIR / f'{car.hex()}.vdv-cert').read_bytes())
    tag_certificate = certificate.take(2)
    assert (tag_certificate == b'\x7f\x21')
    certificate.take_length()
    tag_content = certificate.take(2)
    assert (tag_content == b'\x5f\x4e')
    return RsaKey(certificate.take(certificate.take_length()))


def recover_message(signature: bytes, remainder: bytes, key: RsaKey) -> bytes:
    """Verifies an ISO 9796-2 signature and returns the message recovered from it."""
    recovered = pow(int.from_bytes(signature, 'big'), key.exponent, key.modulus).to_bytes(len(signature), 'big')
    message = recovered[1:-SHA1_SIZE - 1] + remainder
    sha1 = recovered[-SHA1_SIZE - 1:-1]
    if recovered[0] != 0x6a or recovered[-1] != 0xbc or hashlib.sha1(message).digest() != sha1:
        raise ValueError('Invalid signature')
    return message


def parse_compact_datetime(value: int) -> datetime:
    return datetime(
        (value >> 25) + 1990,
        value >> 21 & 0xf,
        value >> 16 & 0x1f,
        value >> 11 & 0x1f,
        value >> 5 & 0x3f,
        (value & 0x1f) * 2,
    )


class VdvTicket:
    def __init__(self, message: bytes):
        data = ByteStringTaker(message)
        self.ticket_id = data.take_int(4)
        self.issuer_org_id = data.take_int(2)
        self.product_id = data.take_int(2)
        self.operator_org_id = data.take_int(2)
        self.valid_from = parse_compact_datetime(data.take_int(4))
        self.valid_until = parse_compact_datetime(data.take_int(4))
        tag_product_data = data.take(1)
        assert (tag_product_data == b'\x85')
        product_data = ByteStringTaker(data.take(data.take_length()))

        blocks = {}
        while not product_data.completely_processed():
            tag = product_data.take(1)
            blocks[tag] = product_data.take(product_data.take_length())

        traveler = ByteStringTaker(blocks[b'\xdb'])
        traveler.take(1)  # gender
        birth_date = traveler.take(4).hex()
        self.birth_date = f'{birth_date[:4]}-{birth_date[4:6]}-{birth_date[6:]}'
        self.name = traveler.unprocessed_data.decode().replace('#', ' ')


class VdvKa:
    def __init__(self, blob: bytes):
        file_bytes = ByteStringTaker(blob)
        self.tag_signature = file_bytes.take(1)
        assert (self.tag_signature == b'\x9e')
        self.length_signature = file_bytes.take_length()
        assert (self.length_signature == 128)
        self.signature = file_bytes.take(self.length_signature)
        self.tag_signature_remainder = file_bytes.take(1)
        assert (self.tag_signature_remainder == b'\x9a')
        self.signature_remainder_length = file_bytes.take_length()
        self.signature_remainder = file_bytes.take(max(self.signature_remainder_length, 5))
        self.version = self.signature_remainder[-2:]
        self.tag_cv_certificate = file_bytes.take(2)
        assert (self.tag_cv_certificate == b'\x7f\x21')
        self.length_cv_certificate = file_bytes.take_length()
        assert (self.length_cv_certificate == 200)
        self.cv_certificate = file_bytes.take(self.length_cv_certificate)
        self.tag_car = file_bytes.take(1)
        assert (self.tag_car == b'\x42')
        self.length_car = file_bytes.take_length()
        assert (self.length_car == 8)
        self.car = file_bytes.take(self.length_car)

        assert (file_bytes.completely_processed())

        certificate_bytes = ByteStringTaker(self.cv_certificate)
        cert_tag = certificate_bytes.take(2)
        assert (cert_tag == b'\x5f\x37')
        cert_length = certificate_bytes.take_length()
        assert (cert_length == 192)
        self.cert_signature = certificate_bytes.take(cert_length)
        cert_signature_remainder_tag = certificate_bytes.take(2)
        assert (cert_signature_remainder_tag == b'\x5f\x38')
        cert_signature_remainder_length = certificate_bytes.take_length()
        self.cert_signature_remainder = certificate_bytes.take(cert_signature_remainder_length)

        assert (certificate_bytes.completely_processed())

        cv_key = RsaKey(recover_message(self.cert_signature, self.cert_signature_remainder, load_ca_key(self.car)))
        self.ticket = VdvTicket(recover_message(self.signature, self.signature_remainder, cv_key))

    def print(self):
        print(f'Signature:            {self.signature.hex(" ")}\n'
              f'Version:              {self.version.hex(" ")}\n'
              f'Cert signature:       {self.cert_signature.hex(" ")}\n'
              f'Cert sig remainder:   {self.cert_signature_remainder.hex(" ")}\n'
              f'CAR:                  {self.car.hex(" ")}\n'
              f'Ticket ID:            {self.ticket.ticket_id}\n'
              f'Issuer org ID:        {self.ticket.issuer_org_id}\n'
              f'Product ID:           {self.ticket.product_id}\n'
              f'Operator org ID:      {self.ticket.operator_org_id}\n'
              f'Valid from:           {self.ticket.valid_from}\n'
              f'Valid until:          {self.ticket.valid_until}\n'
              f'Name:                 {self.ticket.name}\n'
              f'Birth date:           {self.ticket.birth_date}')


def main():
    with open('aztec.bin', 'rb') as f:
        content = f.read()

    vdv_ka = VdvKa(content)
    vdv_ka.print()


if __name__ == '__main__':
    main()
