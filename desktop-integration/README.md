# Desktop OS integration

This overlay supplies session defaults and system integration for the enzUI desktop.

## Gaming compatibility

The installer supplies the signed `steam-devices` package and loads `uinput` and
`joydev`. Its maintained Valve device rules use `uaccess`/mode 0660. Logind grants
access to the active local seat; users are not added to the broad `input` group.
This supports Steam Input for native and Flatpak Steam without a root controller
service or world-writable devices. `ntsync`, GameMode, multilib Mesa/Vulkan and
32-bit audio libraries were already part of the baseline.

`enzimos-gaming-check` (`enzimos-policy desktop gaming-check`) prints bounded, local JSON diagnostics. It does not read
controller/keyboard events, device serials, install software, change Flatpak
permissions, start GameMode or download a game. An unavailable optional package is
reported as null. Direct GameMode bus permission in Flatpak metadata is reported
separately; the Steam runtime can use the GameMode portal without that permission.

The canonical per-user `background.slice` has CPUWeight 20 and IOWeight 10.
The existing local inference service joins it and uses idle I/O priority while
retaining its memory/CPU limits. Backup, scrub, deferred maintenance and home
history join the root-level `enzimosbackground.slice` with the same relative
weights, retaining their existing nice/idle settings. These are contention weights,
not guaranteed frame times or a hard cap on ordinary apps. No new scheduling daemon,
custom kernel, global process renice, GPU overclock or shader-cache override is added.
GUI file-copy workers need the framework handoff to use the background slice.

Steam, Gamescope and `linuxconsole` remain optional. The separate gaming fixture
seed does not expand the installer bundle. Hybrid GPUs, physical controller
Bluetooth/haptics, individual game titles and physical audio still need acceptance;
test these in a disposable installed system.

## Everyday devices

The installer configures printing and mDNS only on a fresh installed target. It
refuses `/`, preserves the vendor CUPS authorization/job ownership policy, validates
all inputs before writing, and does not start services. The installer validates
the resulting scheduler configuration and enables the CUPS socket, Avahi and
IPP-over-USB. Ordinary updates do not run this helper or re-enable administrator
disabled services. Printer sharing and CUPS web administration remain off; IPP USB
listens only on loopback, with bounded error-only logs and printer access for CUPS.
Avahi does not publish workstation/hardware information or reflect discovery
between networks. The incoming trusted-zone rule and ordered HOST-output policies permit mDNS
only on explicitly trusted connections; other network traffic is unaffected. No SSH/SMB server, ADB or automatic phone mounting is enabled.

The reviewed seed supplies CUPS/filters/Ghostscript (PostScript and raster conversion), `cups-pk-helper`, `ipp-usb`, `gvfs-smb`,
`gvfs-mtp`, OpenSSH's SFTP client and NetworkManager OpenVPN/OpenConnect plugins.
WireGuard uses NetworkManager's native implementation. CUPS administration uses
the maintained `org.opensuse.CupsPkHelper.Mechanism` polkit service; ordinary users
do not gain a blanket printer administration group or unrestricted bus access.

Connectivity uses NetworkManager's existing Arch HTTP probe, every 300 seconds
with a five-second timeout and no user/device identifiers. The desktop must expose
disabled/unknown/limited/portal/full accurately, an explicit browser sign-in action
and the existing NM check-enable privacy setting. HTTP detects interception; it
does not authorize disabling TLS validation or entering credentials automatically.


## Session integration

- `enzimos-policy desktop setup` (run by the installer and the package hook) adds managed optional keyring rules to existing greetd, lock and passwd
  PAM files. Existing authentication/account controls are retained. Administrator
  keyring rules are respected. The known vendor global socket autostart link
  is removed so PAM owns first-login startup; an upgrade hook restores this
  policy. No password enters this helper.
  It also supplies greetd's missing distribution password stack for the patched
  PAM expired-password conversation, preserving administrator-provided stacks.
  Fresh installs use this same Rust policy instead of a separate implementation.
- [Public login appearance](LOGIN_APPEARANCE.md) uses an explicit owner-approved
  System1 publication. Root-owned bounded presentation data and canonical images
  are separate from private home preferences. Qualification status is reported
  through the capability flags described in the protocol.
- `enzimos-input-method.service` is a per-user Fcitx5 unit. The managed session starts
  it only for accounts that opted in, after importing Wayland environment, and
  stops it on logout. It is not globally
  enabled by the installer and never runs on the greeter/recovery screen.
- Diagnostic launchers inherited through codec/input dependencies, Avahi
  service browsing and hwloc topology tools are hidden from
  the default app list, and Fcitx generic autostart is replaced by managed startup.
- `session-environment.json` records producer environment requirements. GTK Wayland
  uses native text-input; legacy X11/Qt/SDL clients use their Fcitx bridges.
- UPower owns the single critical battery action at 3%; shell warnings are at
  10%/5%. Capability-based Auto avoids an unqualified hibernation or competing
  shell action. Suspend-only is an explicit administrator preference.
- Coredump policy retains local crash metadata without raw process memory by default.
  The administrator opt-in example caps each core and aggregate storage.
- `enzimos-policy desktop crash-reports` returns only this UID's bounded crash metadata. No journal
  message body, process environment, command line or raw core is returned.

Dependencies are declared by the reviewed `desktop-parity-seed.json` in manifests.
Zen is the only default foreign GUI app. Transitive service/library packages
contain some diagnostic GUI executables; their desktop launchers are masked,
while the libraries and command-line tools remain available. These packages
provide services, input engines and codec modules. The keyring can require unlock when
login uses no password or the keyring has a different password: never silently
create an unencrypted keyring or pretend it is unlocked.

The installer calls setup in the target after applying the desktop overlay. The
producer must adopt the session contract before input methods are qualified.
A source test alone does not prove installed CJK input, Secret Service login or
crash UI behavior.

## Sources

GNOME documents [PAM keyring unlock and password changes](https://wiki.gnome.org/Projects/GnomeKeyring/Pam).
Fcitx documents [Wayland and toolkit environment choices](https://fcitx-im.org/wiki/Using_Fcitx_5_on_Wayland/en).
Systemd documents [coredump retention controls](https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html).

Input method defaults are added to `/etc/environment` only for missing keys;
existing administrator values remain authoritative and GTK_IM_MODULE is not set.
The managed shell starts Fcitx according to account choice, not XDG autostart.
CJK engine packaging requires CJK fonts.

Keyring login collection creation uses PAM startup rather than early global
socket activation. Setup removes only the vendor global socket link, and the
package transaction hook restores this policy on upgrades. The greeter skips
keyring PAM modules; regular users retain optional unlock/start.

AccountsService AppFilter XML and its upstream polkit policy are exact licensed
data from the reviewed malcontent archive. See installed provenance and LGPL text.
Defaults allow all apps; administrator authentication remains required to change
filters. No foreign control GUI, PAM lockout, web filter, or timer daemon is added.
Policy actions for unshipped interfaces do not implement those capabilities.

## User switching provider

`org.enzimos.UserSwitch1` is system D-Bus activated and exits after idle. It exposes
`OpenGreeter()` and `ActivateExisting(session_id)`. Calls are serialized without a
queue, have a shared 20 second deadline, and accept only logind verified local
seat0 callers. Opening requires an active, locked graphical user session. Returning
requires the active `greeter` account's greetd session and a locked graphical user
target on that seat. No passwords, client selected units, VTs, paths, or session
termination requests are accepted.

VT1 remains the primary session, VT2 remains the console, and VT3–6 are reserved
for at most four extra greetd instances. Idle greeters are reused; units holding
logged-in sessions are never restarted. The pool's getty masks apply only when
this optional integration overlay is installed. A missing or exhausted provider
must keep the frontend action unavailable or report refusal.

Test two-account lock/switch/return and pool exhaustion in an installed guest.
Systemd's `Session.Activate` uses `org.freedesktop.login1.chvt` without target
polkit details, so no blanket greeter chvt grant is installed. The restricted
`ActivateExisting` method verifies the target before its privileged activation.
