from schuberth_dfu.catalog import (FAMILY_CSR, family_for_pid, load_catalog,
                                   product_for_pid)


def test_catalog_loads():
    cat = load_catalog()
    assert len(cat) >= 179
    assert cat[0x3170] == "SC2"
    assert cat[0x6510] == "ST1"
    assert cat[0x3020] == "PRISM"
    assert cat[0x5622] == "SC1A"


def test_product_lookup():
    assert product_for_pid(0x3170) == "SC2"
    assert product_for_pid(0x9999) is None


def test_families():
    assert family_for_pid(0x3170) == FAMILY_CSR
    assert family_for_pid(0x3020) == "prism"
    assert family_for_pid(0x6510) == "airoha"
    assert family_for_pid(0x6814) == "airoha"  # DFU-mode range
    assert family_for_pid(0x9999) is None
