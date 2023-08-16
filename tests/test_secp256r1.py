import asyncio
from binascii import unhexlify
from collections import namedtuple
import json
import pytest
import pytest_asyncio
import re
import warnings

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.testing.starknet import Starknet
from starkware.starkware_utils.error_handling import StarkException


def to_uint(a):
    return (a & ((1 << 128) - 1), a >> 128)


def get_wycheproof_testcases(groups_only=False):
    with open("tests/ecdsa_secp256r1_sha256_test.json", "r") as f:
        ret_params = []
        test_groups = json.load(f)["testGroups"]
        tg_index = 0
        if groups_only:
            test_case = namedtuple("test_case", ["tg_index", "key"])
        else:
            test_case = namedtuple(
                "test_case", ["tg_index", "test_id", "comment", "key", "test"]
            )
        for test_group in test_groups:
            if groups_only:
                ret_params.append(
                    test_case(
                        tg_index,
                        test_group["key"],
                    )
                )
                tg_index += 1
            else:
                for test in test_group["tests"]:
                    test_id = test["tcId"]
                    comment = re.sub("[^0-9a-zA-Z]", "_", test["comment"].lower())
                    ret_params.append(
                        test_case(
                            tg_index,
                            test_id,
                            comment,
                            test_group["key"],
                            test,
                        )
                    )
                tg_index += 1
        return ret_params


@pytest.fixture(scope="module")
def event_loop(request):
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="module")
async def init_contracts():
    main_def = compile_starknet_files(
        files=["src/main.cairo"], debug_info=True, disable_hint_validation=False
    )
    starknet = await Starknet.empty()

    main_contract = await starknet.deploy(
        contract_class=main_def,
    )
    return main_contract


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_case",
    get_wycheproof_testcases(),
    ids=lambda tuple: "tg-{} tc-{} title-{}".format(*tuple),
)
async def test_is_valid_sig_sanity_secp256r1_indexed(init_contracts, test_case):
    main_contract = init_contracts

    key = [
        *to_uint(int.from_bytes(unhexlify(test_case.key["wx"]), "big")),
        *to_uint(int.from_bytes(unhexlify(test_case.key["wy"]), "big")),
    ]
    unexpected_exception = False
    try:
        r, s = decode_dss_signature(unhexlify(test_case.test["sig"]))
        digest = hashes.Hash(hashes.SHA256())
        digest.update(unhexlify(test_case.test["msg"]))
        digest_bytes = digest.finalize()

        digest_int = int.from_bytes(digest_bytes, "big", signed=False)
        try:
            _ = await main_contract.verify_secp256r1_sig(
                list(to_uint(digest_int)), [*to_uint(r), *to_uint(s)], key
            ).call()
            warnings.warn(UserWarning("{}".format(_)))
        except StarkException as err:
            if test_case.test["result"] != "invalid":
                unexpected_exception = True
                raise err

    except Exception as e:
        if unexpected_exception:
            raise e
        pytest.skip(
            f"skipped while parsing {test_case.tg_index}, {test_case.test_id}, {test_case.comment}: {e}"
        )

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "test_case",
    get_wycheproof_testcases(groups_only=True),
    ids=lambda tuple: "tg-{}".format(*tuple),
)
async def test_verify_point(init_contracts, test_case):
    main_contract = init_contracts

    key = [
        *to_uint(int.from_bytes(unhexlify(test_case.key["wx"]), "big")),
        *to_uint(int.from_bytes(unhexlify(test_case.key["wy"]), "big")),
    ]
    _ = await main_contract.verify_secp256r1_point(key).call()
    print(_)
