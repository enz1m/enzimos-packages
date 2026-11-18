# Public per-user sign-in appearance

System1 `GetCapabilities.login_appearance` advertises the optional
`LoginAppearance(sh)->s` method. It publishes presentation data only. It does not
change session locking, power policy, authentication or private preferences.
Runtime and shell integration qualification remain separate capability flags.

The caller must be an active local graphical user. System1 derives the UID from
the original system-bus sender, requires fresh polkit `auth_self` authorization
(`org.enzimos.system.login-appearance`, no retained authorization), and rechecks
the session and account immediately before publication. No supplied UID or path
is accepted. A visible UI must explain that selected appearance/image becomes
public before sending `public_consent: true`.

The first argument is this bounded JSON string (all fields required):

```json
{
  "schema": 1,
  "action": "publish",
  "allow_interaction": true,
  "public_consent": true,
  "appearance": {
    "show_time": true,
    "show_date": true,
    "clock_24h": true,
    "reduced_motion": false,
    "material": "glass",
    "layout": "centered",
    "size": "medium",
    "font": "Fredoka",
    "weight": 600,
    "hide_wallpaper_clock": true,
    "hide_wallpaper_date": true,
    "background": {"kind": "default"}
  }
}
```

Materials: `glass`, `frosted_glass`, `simple`. Layouts: `centered`, `split`,
`stacked`, `corner` (the UI calls the last three Duet, Portrait and Horizon).
Sizes: `small`, `medium`, `large`. A font is a bounded installed family name,
never a font file; weights are integers 1–1000. Unknown fields are refused.

The second argument is an anonymous memfd belonging to that same user, mode
0600, link count zero, with WRITE/GROW/SHRINK/SEAL seals. Its file offset is
irrelevant. It is empty for `default`, or for `{"kind":"scene","id":"ID"}`.
Scene IDs are simple names beneath root-owned `/usr/share/enzui/enzwall/scenes`;
the selected directory and bounded `scene.toml` must be protected system files.
No user package publication, executable, plugin, shader or source path is supported.

For `{"kind":"image"}`, supply PNG bytes in the sealed FD. Import/resize in
the ordinary user's bounded importer first: maximum 960×540, 8-bit RGB/RGBA,
noninterlaced, 3 MiB encoded. The backend checks the complete chunk/CRC structure,
exact bounded decompressed rows and zlib closure, then reencodes only IHDR/IDAT/IEND.
Metadata, profiles, source paths and animation are not published. Malformed,
excessive or truncated images leave the previous publication unchanged.

System1 atomically replaces `/var/lib/enzimos-login-appearance/UID.json`, mode
0644 in a root-owned 0755 directory, outside private OS state. The single bounded
document contains `{schema:1, uid, account, published, appearance,
image_png_base64}`. The optional image is canonical PNG encoded as base64; there
are no dependent image files or paths to race, leak or accumulate. A successful
reply is `{schema:1,published:true,public:true}`. A lost reply must not trigger an
automatic retry; read the public document to observe the outcome.

To revoke, send `{"schema":1,"action":"clear","allow_interaction":true}`
with an empty sealed FD. An atomic tombstone has `published:false`, null appearance
and null image. Already copied public data cannot be recalled.

The greeter must check protected root ownership, bounded file size (4 MiB),
schema, selected account name and UID, and `published:true` before consumption.
Read one complete file, never reopen image or private-home paths. Treat invalid,
missing, revoked or mismatched data as shared defaults. Preserve the existing
bounded live renderer sandbox and still fallback; a publication grants no execution
or authentication authority. Account removal should explicitly clear the publication;
matching both UID and account name prevents an unrelated UID reuse from inheriting it.

Installed polkit/publication and greeter consumption must be validated together
before enabling this optional capability in a desktop session.
