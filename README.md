# Hark Apps (Home Assistant app repository)

Also in this repository: the **Navien Recirc Boost** integration (see below).

- **Hark HA Gateway** (`hark_gateway`): prints Hark's documents and receipts on your network printers, and lets Hark run
  network tools on your home network. Looking is automatic; any change waits for your approval, signed with a key only
  Hark holds. Hark reaches it through your Home Assistant; no port forwarding, nothing to paste.

Add this repository in Home Assistant: Settings > Apps > App store > ⋮ > Repositories:
`https://github.com/kdttocs/HA`

This repository holds no secrets, device addresses or server addresses. The app gets everything it needs from Hark
through Home Assistant when it pairs, and keeps it in the app's private `/data` folder.

Security notes: see `hark_gateway/DOCS.md` ("Approval for changes", "What the app will and won't touch").

---

## Navien Recirc Boost

A Home Assistant integration (installed with HACS, the Home Assistant Community Store) for Navien tankless heaters
that run their recirculation pump on the heater's own **weekly schedule**, such as the NPE-2 series.

In schedule mode these heaters ignore the NaviLink "Hot Button". Navien Recirc Boost gives you a **Boost** button
that heats the hot-water loop anyway, then puts your schedule back exactly as it was.

### What a boost does
1. Reads the heater's current weekly schedule (so it can be restored exactly).
2. Turns the schedule off. The recirculation pump starts and the burner heats the loop.
3. Watches the water returning to the heater until it is within the **stop offset** of the heater's target
   temperature (default 5 degrees; for example 125 °F when the heater is set to 130 °F).
4. Runs **extra minutes** (default 2), never longer than the **safety cap** (default 15 minutes in total).
5. Turns the schedule back to how it was, retrying up to 4 times. If that fails you get a Home Assistant
   notification. If Home Assistant restarts during a boost, the schedule is restored when it starts again.

### What you get
| Entity | What it is |
| --- | --- |
| Boost (button) | Start a boost |
| Stop boost (button) | Finish a boost early (the schedule is still restored) |
| Boost running (binary sensor) | On during a boost; attributes show the phase and stop temperature |
| Schedule (sensor) | On/off, with one attribute per day, e.g. `monday: 05:00-09:00, 16:30-22:00`. Read at startup and hourly |
| Weekly schedule (switch) | Turn the heater's own schedule on or off (its windows are kept) |
| Target temperature (number) | The heater's set temperature |
| Boosts today, Boosts total, Last boost (sensors) | Boost tracker; kept across restarts. "Today" resets at midnight |
| Return water temperature, Outlet temperature (sensors) | Water coming back to / leaving the heater |
| NaviLink connected (binary sensor) | Cloud connection status |

Actions (services) for automations: `navien_recirc_boost.boost` (optionally override the stop offset, extra minutes and
safety cap), `navien_recirc_boost.stop_boost`, `navien_recirc_boost.refresh_schedule`, and
`navien_recirc_boost.set_day_schedule` (e.g. `day: monday`, `windows: "05:00-09:00, 16:30-22:00"`, or `off`).

### Install
1. In HACS: ⋮ > Custom repositories > add `https://github.com/kdttocs/HA`, type **Integration**.
2. Download **Navien Recirc Boost**, then restart Home Assistant.
3. Settings > Devices & services > Add integration > **Navien Recirc Boost**, and sign in with your NaviLink
   app email and password.

### Settings
Settings > Devices & services > Navien Recirc Boost > **Configure**:
- **Boost settings**: stop offset (degrees below target, e.g. 3, 4, 5), extra run time, safety cap.
- **Weekly schedule**: shows the heater's whole week as read from the heater, one line per day, plus a
  Schedule on switch. Edit any day (24-hour clock, up to 4 windows like `05:00-09:00, 16:30-22:00`, or `off`)
  and submit; only the days you changed are sent to the heater, right away.

### Notes
- It signs in to NaviLink on its own and does not need any other Navien integration. It can run alongside
  another NaviLink integration; each connection uses its own random client ID.
- Don't run two boost controllers at once (for example an older script that also toggles the schedule).
- Tested against an NPE-2 (NaviLink device type 2). Setting a day to `off` and windows on minutes other than
  :00/:30 have not been tried on a real heater yet.

### Credits
The NaviLink sign-in and messaging code in `custom_components/navien_recirc_boost/navilink/` comes from
[lasswellt/navien-homeassistant](https://github.com/lasswellt/navien-homeassistant) (MIT License); see
`custom_components/navien_recirc_boost/NOTICE`.

Developer tests: `pip install pytest-homeassistant-custom-component paho-mqtt`, then
`PYTHONPATH=. pytest tests -o asyncio_mode=auto`.
