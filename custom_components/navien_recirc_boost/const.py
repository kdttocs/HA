"""Constants for Navien Recirc Boost."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "navien_recirc_boost"
MANUFACTURER: Final = "Navien"

CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"
CONF_DEVICE_INDEX: Final = "device_index"

# Boost options
CONF_STOP_OFFSET: Final = "stop_offset"
CONF_EXTRA_MINUTES: Final = "extra_minutes"
CONF_MAX_MINUTES: Final = "max_minutes"

DEFAULT_STOP_OFFSET: Final = 5  # degrees below the heater's target
DEFAULT_EXTRA_MINUTES: Final = 2
DEFAULT_MAX_MINUTES: Final = 15

# How often the NaviLink client asks the heater for its status (seconds).
POLL_INTERVAL: Final = 30
# How often the weekly schedule is re-read from the heater.
SCHEDULE_REFRESH_HOURS: Final = 1
# How often the boost checks the return-water temperature (seconds).
BOOST_CHECK_SECONDS: Final = 10
# Turning the schedule back on: attempts and pause between them.
RESTORE_ATTEMPTS: Final = 4
RESTORE_RETRY_SECONDS: Final = 20
# Used only if the heater's target temperature is unknown.
FALLBACK_STOP_TEMP_F: Final = 125

WEEKLY_ON: Final = 1
WEEKLY_OFF: Final = 2

DAY_NAMES: Final = {
    1: "sunday",
    2: "monday",
    3: "tuesday",
    4: "wednesday",
    5: "thursday",
    6: "friday",
    7: "saturday",
}
MAX_WINDOWS_PER_DAY: Final = 4

STORAGE_VERSION: Final = 1

SERVICE_BOOST: Final = "boost"
SERVICE_STOP_BOOST: Final = "stop_boost"
SERVICE_SET_DAY_SCHEDULE: Final = "set_day_schedule"
SERVICE_REFRESH_SCHEDULE: Final = "refresh_schedule"
