# macOS Signing

On macOS, Alioth uses the
[Hypervisor](https://developer.apple.com/documentation/hypervisor) framework to
create virtual machines and the
[vmnet](https://developer.apple.com/documentation/vmnet) framework for virtual
networking. Both frameworks require special entitlements.

To run Alioth without root privileges, the binary must be signed with the
necessary entitlements. You can self-sign the binary using the following
command:

```bash
codesign -s - --entitlements /path/to/cli.entitlements --force /path/to/alioth
```
