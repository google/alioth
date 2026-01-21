//go:build tools

package initramfs

import (
	_ "github.com/u-root/u-root/pkg/boot"
	_ "github.com/u-root/u-root/pkg/boot/menu"
	_ "github.com/u-root/u-root/pkg/libinit"
)
