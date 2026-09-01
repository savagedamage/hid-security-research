# Experiment: Validate Linux USB/HID Lifecycle Monitoring

Status: protocol defined; not executed in the current Android/Termux environment
because `/sys/bus/usb/devices` is not readable there.
Last reviewed: 2026-08-31

## Purpose

Validate `hidwatch monitor` against authorized physical devices while collecting
only enumeration metadata—not keystroke content.

## Safety and privacy

- Use only devices and hosts you own or are authorized to test.
- Do not open or read `/dev/hidraw*` in this experiment.
- Do not type passwords or sensitive content.
- The expected output contains topology name, device-asserted identity,
  interface-derived role, risk level, product string, and finding reasons.
- Remember VID/PID/serial/product are claims, not authenticated identity.

## Setup

Linux host with readable `/sys/bus/usb/devices`; project installed in a virtual
environment. Prepare one ordinary keyboard, one mouse, and—if authorized—a
benign composite keyboard/media-key device. Do not use weaponized payloads.

## Procedure

1. Record kernel and distribution versions.
2. Start `hidwatch monitor --all --interval 0.25` with no test devices attached.
3. Attach each device once, wait two seconds, then detach it.
4. For a composite keyboard, confirm the monitor classifies it as HID/keyboard
   and does not invent interfaces.
5. Run `hidwatch list --all` and compare topology, VID/PID, strings, and
   interfaces to `lsusb -t` and the relevant sysfs entries.
6. Reconnect a device to a different physical port and confirm the topology name
   changes; do not interpret that as cryptographic identity change.
7. Suspend/resume the host and record whether the resulting lifecycle events are
   noisy or misleading.
8. Stop with Ctrl-C and confirm graceful shutdown.

## Acceptance criteria

- Every deliberate attach and detach appears once within two poll intervals.
- Interface entries are associated with the correct sibling device (`1-1:1.0`
  with `1-1`, never with prefix-collision device `1-10`).
- No raw report or decoded keystroke content is captured.
- Inaccessible sysfs produces a clear unavailable message, not fabricated data.
- CPU use and event latency are recorded for later udev comparison.

## Record results

Create a dated page under this directory containing host/device metadata,
observed event counts, missed/duplicate events, latency range, discrepancies,
and evidence label (`observed`). Redact serial numbers if publishing them.
