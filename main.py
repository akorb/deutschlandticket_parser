class ByteStringTaker:
    __slots__ = ['unprocessed_data']

    def __init__(self, byte_str: bytes):
        self.unprocessed_data = byte_str

    def take(self, n):
        chunk = self.unprocessed_data[:n]
        self.unprocessed_data = self.unprocessed_data[n:]
        return chunk

    def completely_processed(self):
        return len(self.unprocessed_data) == 0


class VdvKa:
    def __init__(self, blob: bytes):
        file_bytes = ByteStringTaker(blob)
        self.tag_signature = file_bytes.take(1)
        assert (self.tag_signature == b'\x9e')
        self.length_signature = file_bytes.take(2)[1]
        assert (self.length_signature == 128)
        self.signature = file_bytes.take(self.length_signature)
        self.tag_signature_remainder = file_bytes.take(1)
        assert (self.tag_signature_remainder == b'\x9a')
        self.signature_remainder_length = file_bytes.take(1)[0]
        self.signature_remainder = file_bytes.take(max(self.signature_remainder_length, 5))
        self.version = self.signature_remainder[-2:]
        self.tag_cv_certificate = file_bytes.take(2)
        assert (self.tag_cv_certificate == b'\x7f\x21')
        self.length_cv_certificate = file_bytes.take(2)[1]
        assert (self.length_cv_certificate == 200)
        self.cv_certificate = file_bytes.take(self.length_cv_certificate)
        self.tag_car = file_bytes.take(1)
        assert (self.tag_car == b'\x42')
        self.length_car = file_bytes.take(1)[0]
        assert (self.length_car == 8)
        self.car = file_bytes.take(self.length_car)

        assert (file_bytes.completely_processed())

        certificate_bytes = ByteStringTaker(self.cv_certificate)
        cert_tag = certificate_bytes.take(2)
        assert (cert_tag == b'\x5f\x37')
        cert_length = certificate_bytes.take(2)[1]
        assert (cert_length == 192)
        self.cert_signature = certificate_bytes.take(cert_length)
        cert_signature_remainder_tag = certificate_bytes.take(2)
        assert (cert_signature_remainder_tag == b'\x5f\x38')
        cert_signature_remainder_length = certificate_bytes.take(1)[0]
        self.cert_signature_remainder = certificate_bytes.take(cert_signature_remainder_length)

        assert (certificate_bytes.completely_processed())

    def print(self):
        print(f'Signature:            {self.signature.hex(" ")}\n'
              f'Version:              {self.version.hex(" ")}\n'
              f'Cert signature:       {self.cert_signature.hex(" ")}\n'
              f'Cert sig remainder:   {self.cert_signature_remainder.hex(" ")}\n'
              f'CAR:                  {self.car.hex(" ")}')


def main():
    with open('aztec.bin', 'rb') as f:
        content = f.read()

    vdv_ka = VdvKa(content)
    vdv_ka.print()


if __name__ == '__main__':
    main()
