module initramfs

go 1.24.8

require github.com/u-root/u-root v0.15.1-0.20260130184054-1d77f99544ea // indirect

require (
	github.com/cenkalti/backoff/v4 v4.1.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/rekby/gpt v0.0.0-20200219180433-a930afbc6edc // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/u-root/cpuid v0.0.1-0.20250320140348-cc5fe81d966c // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/vishvananda/netlink v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/term v0.37.0 // indirect
	pack.ag/tftp v1.0.1-0.20181129014014-07909dfbde3c // indirect
)

tool (
	github.com/u-root/u-root/cmds/boot/boot
	github.com/u-root/u-root/cmds/core/init
)
