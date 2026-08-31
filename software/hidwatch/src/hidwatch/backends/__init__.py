"""hidwatch backends: read-only observation sources.

Currently: Linux sysfs. Future: udev events, hidraw, usbmon (docs/usb-hid.md §5).
All backends are strictly non-destructive.
"""
