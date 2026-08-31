# Hardware Prototype Plan

Status: no hardware prototype built or tested yet.

1. Select dual-role hardware capable of concurrent downstream USB host and
   upstream USB device/gadget operation; document electrical and USB compliance.
2. Tier T2, detect-only: enumerate a keyboard, capture descriptor, re-present a
   fixed boot-keyboard interface, forward reports, and measure added latency.
3. Feed metadata into the hidwatch parser/analyzer; store local tamper-evident
   event logs without decoded keystroke content.
4. Build a compatibility matrix across standard, gaming, media, composite,
   macro, scanner, mouse, and controller fixtures/devices.
5. Only after detect-only stability, add quarantine/physical approval, report
   conformance, rate limits, and descriptor normalization one policy at a time.
6. Fuzz both USB-facing parsers and test power loss, malformed descriptors,
   disconnect/re-enumeration, boot protocol, suspend/resume, and host reboot.

Candidate platforms must be evaluated rather than preselected. Raspberry Pi USB
gadget setups are convenient but may lack robust dual-controller isolation;
LUNA/Cynthion-class FPGA boards offer observability but require substantially
more engineering. No platform is endorsed before measured tests.
