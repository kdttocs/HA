"""Test fixtures: a fake NaviLink client so nothing touches the cloud."""

from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import time
from unittest.mock import patch

import pytest

pytest_plugins = ["pytest_homeassistant_custom_component"]

SCHEDULE = json.loads(
    (pathlib.Path(__file__).parent / "live_sched_response.json").read_text()
)["channel"]["weeklySchdList"]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


class FakeChannel:
    def __init__(self, client):
        self.client = client
        self.number = 1
        self.info = {"temperatureType": 2, "setupDHWTempMin": 97, "setupDHWTempMax": 140}
        self.status = {
            "DHWSettingTemp": 130,
            "weeklyControl": 1,
            "unitInfo": {"unitStatusList": [{"currentInletTemp": 90, "currentOutletTemp": 128}]},
        }
        self.temps = []

    async def set_temperature(self, value):
        self.temps.append(value)
        self.status["DHWSettingTemp"] = value


class FakeClient:
    instances: list = []

    def __init__(self, username, password, *, session, device_index=0, poll_interval=15):
        self.username = username
        self.password = password
        self.connected = False
        self.on_update = None
        self.weekly = {}
        self.schedule = copy.deepcopy(SCHEDULE)
        self.writes = []
        self.channels = {}
        self.device_info = {"deviceInfo": {"macAddress": "047863305f7a", "deviceName": "NPE2", "additionalValue": "x"}}
        self.devices = [self.device_info]
        self.polls = 0
        self.inlet_rise = 0
        self.fail_writes = 0
        FakeClient.instances.append(self)

    async def async_login(self):
        if self.password == "bad":
            from custom_components.navien_recirc_boost.navilink import AuthenticationError
            raise AuthenticationError("bad")
        return self.devices

    async def async_connect(self):
        self.connected = True
        self.channels = {1: FakeChannel(self)}

    async def async_disconnect(self):
        self.connected = False

    async def async_read_schedule(self, channel, timeout=10.0):
        ch = self.channels[1]
        self.weekly[1] = {"weekly_control": ch.status["weeklyControl"],
                          "schedule": copy.deepcopy(self.schedule), "received": time.monotonic()}
        return self.weekly[1]

    async def async_write_schedule(self, channel, enabled, schedule):
        if self.fail_writes:
            self.fail_writes -= 1
            from custom_components.navien_recirc_boost.navilink import NavilinkError
            raise NavilinkError("nope")
        self.writes.append((enabled, copy.deepcopy(schedule)))
        self.channels[1].status["weeklyControl"] = 1 if enabled else 2
        by_day = {d["day"]: d for d in self.schedule}
        for d in schedule:
            by_day[d["day"]] = d
        self.schedule = [by_day[k] for k in sorted(by_day)]

    async def async_poll(self):
        self.polls += 1
        u = self.channels[1].status["unitInfo"]["unitStatusList"][0]
        u["currentInletTemp"] += self.inlet_rise


@pytest.fixture
def fake_client():
    FakeClient.instances.clear()
    with patch("custom_components.navien_recirc_boost.coordinator.NavilinkClient", FakeClient), \
         patch("custom_components.navien_recirc_boost.config_flow.NavilinkClient", FakeClient), \
         patch("custom_components.navien_recirc_boost.config_flow.async_get_clientsession"), \
         patch("custom_components.navien_recirc_boost.coordinator.async_get_clientsession"):
        yield FakeClient


@pytest.fixture
def fast_boost():
    from custom_components.navien_recirc_boost.boost import BoostController
    real_wait = BoostController._wait

    async def short_wait(self, seconds):
        return await real_wait(self, min(seconds, 0.01))

    with patch.object(BoostController, "_wait", short_wait), patch("custom_components.navien_recirc_boost.boost.BOOST_CHECK_SECONDS", 0.01), \
         patch("custom_components.navien_recirc_boost.boost.RESTORE_RETRY_SECONDS", 0.01), \
         patch("custom_components.navien_recirc_boost.boost.asyncio.sleep", _no_sleep):
        yield


_real_sleep = asyncio.sleep


async def _no_sleep(_s, *a, **k):
    await _real_sleep(0)
