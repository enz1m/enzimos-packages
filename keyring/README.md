# System credential storage

`enzimos-keyring` packages oo7 0.7.1, its PAM module and login helper, CLI,
and Secret portal backend. Native applications use `org.freedesktop.secrets`.
Flatpaks can use the Secret portal. The package replaces GNOME Keyring on the
enzimOS image and conflicts with a second oo7 provider.

After a password login, PAM starts the oo7 login helper and queues the daemon
in the user's systemd manager. The helper passes the password to oo7 through a
sealed file descriptor. The daemon initializes its collections before claiming
the Secret Service bus name. oo7 handles migration of existing keyrings and
updates matching keyrings on password changes. A password reset without the
previous password leaves the old keyring encrypted.

The patch selects `dev.enzui.SecretPrompter` for graphical clients when the
enzUI session is active and the prompt service is available. Other desktops
retain oo7's prompt selection. The package's PAM configuration helper covers
installed greetd, SDDM, GDM and console login stacks and preserves administrator
oo7 rules.

Build with the workspace's `tools/build_keyring.py` from the pinned oo7 revision
after fetching its Cargo dependencies. The offline build includes the source
archive and patch in the package. Install the package in a disposable VM for
login and migration tests.
