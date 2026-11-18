# LinkScope

A small Windows GUI that shows what is actually on each Ethernet cable, and explains why `ping` fails.

`ping` only works when both ends are on the same IP subnet. Underneath IP, Ethernet delivers broadcast frames, such as ARP "who has 1.2.3.4?", to every device on the cable whatever its IP. LinkScope listens to those frames passively, so it can see a device and its real address even when ping can't.

## Features

- **Adapters:** each adapter's IPv4 address and prefix, the range it covers, gateway, and broadcast vs. unicast receive counters. Flags overlapping subnets, self-assigned 169.254 addresses, and "hears broadcasts but nothing has ever replied".
- **Devices heard on the cables:** a background capture on every wired adapter lists each device's MAC, vendor, the IPs it uses, and the addresses it keeps asking for without getting an answer. Each device gets a verdict: reachable, wrong subnet, routed to another adapter, IP used twice, asking for DHCP, and so on.
- **Explanation pane:** a plain-language reason for every verdict, plus a suggested fix (for example, "add 192.168.144.78/24 to Ethernet 2").
- **Why can't I reach X?** Runs a ping, works out which adapter Windows routes the address to, checks ARP, and if the ping fails, shows what is actually on that cable instead.
- **Add IP / Remove IP:** runs `netsh` through the Windows admin prompt.

## Requirements

- Windows 10/11
- Python 3 with tkinter (included in the standard python.org install)
- [Wireshark](https://www.wireshark.org/) with Npcap. Capturing works without admin if Npcap was installed without the "restrict to administrators" option.

No other Python packages are needed.

## Run

Double-click `linkscope.pyw`, or run:

```
pythonw linkscope.pyw
```

### Desktop icon and taskbar

```
powershell -ExecutionPolicy Bypass -File install-shortcut.ps1
```

This creates `LinkScope` shortcuts on the Desktop and in the Start Menu. To pin it, right-click the Desktop icon and choose **Pin to taskbar** (Windows doesn't let scripts pin). The shortcut and the app share an AppUserModelID, so the pinned icon and the running window use one taskbar button.

Run the script again if you move the folder or upgrade Python.

## Limits

- Passive only. A device that stays completely silent until something talks to it won't appear. Power-cycling it while LinkScope is open usually reveals it, because almost every device sends ARP or DHCP while booting.
- Device names appear only if the device announces one (DHCP hostname, LLDP, CDP).
- Wi-Fi isn't listened on by default; there's a checkbox to turn it on.
