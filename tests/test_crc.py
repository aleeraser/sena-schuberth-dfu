from schuberth_dfu.crc import crc16_ccitt, crc32


def test_crc16_ccitt_check_value():
    # CRC-16/XMODEM-style (poly 0x1021, init 0, MSB-first) check value for
    # "123456789"; cross-checked against binascii.crc_hqx(data, 0).
    assert crc16_ccitt(b"123456789") == 0x31C3


def test_crc16_running():
    data = b"123456789"
    running = 0
    for i in range(0, len(data), 3):
        running = crc16_ccitt(data[i:i + 3], running)
    assert running == crc16_ccitt(data)


def test_crc32():
    assert crc32(b"123456789") == 0xCBF43926
