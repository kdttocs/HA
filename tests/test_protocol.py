"""The schedule messages match what the NaviLink app sent (captured Oct 28, 2026)."""

import json
import pathlib

from custom_components.navien_recirc_boost.navilink import protocol
from custom_components.navien_recirc_boost.navilink.client import NavilinkClient

T = protocol.Topics(device_type=2, mac="047863305f7a", home_seq="19119", user_seq="27625", client_id="CID")


def test_read_msg_matches_app():
    msg = protocol.weekly_read_msg(T, "9528", 1)
    assert msg["requestTopic"] == "cmd/2/navilink-047863305f7a/status/weeklyschedule"
    assert msg["responseTopic"] == "cmd/2/19119/27625/CID/res/weeklyschedule"
    assert msg["request"] == {"additionalValue": "9528", "command": 16777222, "deviceType": 2,
                              "macAddress": "047863305f7a", "status": {"channelNumber": 1}}
    assert T.weekly_res in T.subscriptions


def test_write_msg_matches_app():
    day = {"schdList": [{"hh": 8, "num": 1, "flag": 1, "mm": 0}], "day": 1, "schdCnt": 1}
    msg = protocol.weekly_write_msg(T, "9528", 1, True, [day])
    assert msg["requestTopic"] == "cmd/2/navilink-047863305f7a/control/weeklyschedule"
    assert msg["request"]["command"] == 33554438
    assert msg["request"]["control"] == {"channelNumber": 1, "weeklyControl": 1, "weeklyScheduleList": [day]}
    assert protocol.weekly_write_msg(T, "9528", 1, False, [])["request"]["control"]["weeklyControl"] == 2


def test_client_parses_reply():
    reply = json.loads((pathlib.Path(__file__).parent / "live_sched_response.json").read_text())
    client = NavilinkClient("u", "p", session=None)
    client._handle_message("x/res/weeklyschedule", {"response": {"weeklySchedule": reply}})
    got = client.weekly[1]
    assert got["weekly_control"] == 1
    assert len(got["schedule"]) == 7 and got["schedule"][6]["schdCnt"] == 2
