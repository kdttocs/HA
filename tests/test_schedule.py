import pytest

from custom_components.navien_recirc_boost.schedule import (
    ScheduleError, build_day, day_number, day_windows, describe, parse_windows,
)
from .conftest import SCHEDULE


def test_describe_live_schedule():
    d = describe(SCHEDULE)
    assert d["sunday"] == "08:00-10:00, 15:00-22:00"
    assert d["monday"] == "05:00-09:00, 16:30-22:00"
    assert d["friday"] == "05:00-09:00, 16:30-23:00"
    assert d["saturday"] == "08:00-23:00"


def test_round_trip():
    w = parse_windows("16:30-22:00, 5:00-09:00")
    assert w == [(5, 0, 9, 0), (16, 30, 22, 0)]
    day = build_day(2, w)
    assert day == SCHEDULE[1]
    assert day_windows(day) == w


@pytest.mark.parametrize("text", ["5-9", "09:00-05:00", "05:00-09:00, 08:00-10:00",
                                  "25:00-26:00", "1:00-2:00,3:00-4:00,5:00-6:00,7:00-8:00,9:00-10:00"])
def test_bad(text):
    with pytest.raises(ScheduleError):
        parse_windows(text)


def test_off_and_days():
    assert parse_windows("off") == []
    assert build_day(1, []) == {"day": 1, "schdCnt": 0, "schdList": []}
    assert day_number("Monday") == 2 and day_number("sat") == 7 and day_number(1) == 1
    with pytest.raises(ScheduleError):
        day_number("funday")
