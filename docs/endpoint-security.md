# Endpoint Security

`vogterd` tries Apple's Endpoint Security (ES) at startup. When it can't be used,
it says why (`vogter status`) and runs the fallback watchers instead.

| | Endpoint Security | Fallback |
| --- | --- | --- |
| Program launches | every exec, with args and kernel-verified signature | process list polled every second; misses programs that exit sooner; args need root for other users' processes |
| Reads of Keychain, browser cookies/passwords, SSH/AWS/GPG keys, Messages | yes (`open` events, only for those folders) | **no** |
| New background/login items | yes, with which process added it | startup folders watched via FSEvents |
| Permission (TCC) changes | yes, macOS 15.4+ | TCC databases watched via FSEvents (needs Full Disk Access) |
| sudo | yes | sudo's unified-log lines |
| SSH logins, screen sharing sessions | yes | no (health check flags if they're turned on) |
| Lock / unlock | yes | loginwindow's BSD notifications |
| XProtect malware detections | yes | no |

## What ES needs

1. **Root.** Install with `sudo scripts/install-daemon.sh`.
2. **Full Disk Access** for `/Library/PrivilegedHelperTools/com.vogter.vogterd` (where the
   installer puts the root copy).
3. **The `com.apple.developer.endpoint-security.client` entitlement.**
   Request it from Apple: <https://developer.apple.com/contact/request/system-extension/>
   (needs a paid developer account). Once granted, sign with your Developer ID,
   the entitlement and the provisioning profile Apple issues.

## Developing before Apple grants it

Use a macOS virtual machine, **not your main Mac**:

1. Create a macOS VM (UTM or any Virtualization.framework app).
2. In the VM's Recovery: `csrutil disable`, then in the VM:
   `sudo nvram boot-args="amfi_get_out_of_my_way=1"` and reboot.
   This lets ad-hoc-signed binaries claim restricted entitlements.
3. Build there: `ENDPOINT_SECURITY=1 scripts/build-app.sh`
4. Install it as root: `sudo ALLOW_ADHOC=1 scripts/install-daemon.sh build/Vogter.app/Contents/Helpers/vogterd`
   (never run a user-writable binary as root), then grant
   `/Library/PrivilegedHelperTools/com.vogter.vogterd` Full Disk Access when it reports `NotPermitted`.
5. `vogter status` should say `realtime: endpoint_security, fs_events`.

The ES event handling lives in `crates/vogter-es`; all decisions (what is
suspicious) are in `crates/vogter-detect` and are unit-tested without ES.
