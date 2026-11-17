# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
import datetime as dt

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate
from requisition_aws.keys import KeyRegistry
from requisition_aws.registry import ToolRegistry
from requisition_aws.store import Store

from .fake_requisition import FakeRequisition
from .test_canonical import SEED_SCHEMA

ACT_TYPE = "payments.refund_send"
TOOL = "payments_refund_send"


class Clock:
    def __init__(self):
        self.t = dt.datetime(2026, 11, 9, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp()

    def __call__(self):
        return self.t

    def now(self):
        return dt.datetime.fromtimestamp(self.t, dt.timezone.utc)

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def fake(clock):
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now)
    server.base_url = server.start()
    yield server
    server.stop()


@pytest.fixture
def client(fake):
    return Client(fake.base_url, fake.credential, fake.principal, timeout=5)


@pytest.fixture
def store(tmp_path, clock):
    return Store(str(tmp_path / "store.json"), clock=clock)


@pytest.fixture
def gate(client, store, clock, fake):
    keys = KeyRegistry.from_bytes(client.keys())
    return Gate(client, store, approval_base_url="http://127.0.0.1:4103", keys=keys, clock=clock)


@pytest.fixture
def registry():
    r = ToolRegistry()
    r.register(TOOL, ACT_TYPE, SEED_SCHEMA)
    return r


def refund_args(**over):
    args = {"amount_minor": 1250, "currency": "USD", "account": "acct-7781", "reason": "duplicate charge"}
    args.update(over)
    return args
