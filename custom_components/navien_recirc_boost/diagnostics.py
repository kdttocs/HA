"""Diagnostics download (passwords and tokens removed)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_PASSWORD, CONF_USERNAME
from .coordinator import NavienRecircConfigEntry

TO_REDACT = {CONF_PASSWORD, CONF_USERNAME, "macAddress", "additionalValue", "homeSeq", "serialNumber"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: NavienRecircConfigEntry
) -> dict[str, Any]:
    """Return diagnostics."""
    c = entry.runtime_data
    return {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        "connected": c.client.connected,
        "device": async_redact_data(c.device_info_raw, TO_REDACT),
        "channel_info": c.info,
        "channel_status": c.status,
        "schedule": c.schedule,
        "weekly_control": c.weekly_control,
        "boost": c.boost.attributes,
        "saved": {k: v for k, v in c.saved.items() if k != "boost_schedule"},
    }
