# Alioth

Alioth is a toy virtual machine monitor based on KVM. Complementary to the
official tutorial [Using the KVM API](https://lwn.net/Articles/658511/), it demonstrates
detailed steps for building a type-2 hypervisor and booting a Linux guest kernel.

## Get started

* Build Alioth from source,

    ```sh
    cargo build --release --target x86_64-unknown-linux-gnu
    ```

* Make an initramfs with [u-root](https://github.com/u-root/u-root?tab=readme-ov-file#examples),

* Boot a Linux kernel with 2 CPUs and 4 GiB memory:

  ```sh
  cargo run --release --target x86_64-unknown-linux-gnu -- \
      -l info \
      --log-to-file \
      run \
      --kernel /path/to/vmlinuz \
      --cmd-line "console=ttyS0" \
      --initramfs /path/to/initramfs \
      --mem-size 4G \
      --num-cpu=2
  ```


## Disclaimer

Disclaimer: Alioth is not an officially supported Google product.