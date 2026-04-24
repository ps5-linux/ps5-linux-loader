# ps5-linux-loader

This payload let's you boot a Linux kernel on bare metal hardware on the PS5 on firmwares up to 04.51

Currently firmwares 1.xx and 2.xx are not supported. They will be soon.

To do so, it uses a disclosed vulnerability that gives access to Trusted Memory Regions (TMRs).

The process to boot Linux is divided in 3 stages:

- Payload on Prospero OS that disables HV protections to install a shellcode in Kernel mode to be loader on system wake-up and loads Linux boot bins on memory.
- Kernel shellcode that disables HV protections and patches "VMEXIT_HANDLER" to install identity mapping and jump to HV shellcode.
- Hypervisor shellcode (real bare metal) that loads the required structure and boots the Linux kernel.

PLEASE USE AT YOUR OWN RISK. IT MAY DAMAGE YOUR CONSOLE TURNING IT UNREPAIRABLE.

## Credits

[theflow](https://github.com/TheOfficialFloW): Linux kernel patches, main boot config and boot strategy

[c0w](https://github.com/c0w-ar): Loader code and kernel/hv shellcodes

[fail0verflow](https://github.com/fail0verflow): HV defeat vulnerability (https://github.com/fail0verflow/prosperous)

[flatz](github.com/flatz): HV defeat vulnerability (https://gist.github.com/flatz/620ddda6d64acca6d1c990dc3080ac0e)

[cragson](https://github.com/cragson): HV defeat implementation for <= 04.51 on PS5 HEN (https://github.com/cragson/ps5-hen)

[john-tornblom](https://github.com/john-tornblom): PS5 SDK (https://github.com/ps5-payload-dev/sdk)

[echostretch](https://github.com/echostretch): Offsets and testing

## Own compilation

First, install the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)

Second, clone this repository and make

```
git clone git@github.com:c0w-ar/ps5-linux-loader.git

cd ps5-linux-loader

make
```
## Prework

To be able to boot linux, you first have to create a fresh install image of your desired distribution (Ubuntu recommended) on an external USB drive (SSD recommended).

You can use any live CD / USB to install to the external drive. It's recommended that you take note of your partition UUID to use it on the boot command.

Recommended boot command:
```
root=UUID={your-partition-hash} rw rootwait console=ttyTitania0 console=tty0 video=DP-1:1920x1080@60 mitigations=off idle=halt pci=pcie_bus_perf
```

## How to Use

Place the bzImage and initrd.img files on the folder "PS5/Linux/" on your USB drive.

If you wish to customize the Video Ram (vram) or Boot Command you can optionally add the files "vram.txt" and "cmdline.txt".

```
USB0 Root
└── 📁 PS5
    └── 📁 Linux
        └── 📄 bzImage
        └── 📄 initrd.img
        └── 📄 vram.txt (hex string)
        └── 📄 cmdline.txt (custom boot command)
```

Send the payload

```sh
socat -t 99999 - TCP:YOUR_PS5_IP:9021 < ps5-linux-loader.elf
```

Wait until you see the message that is time to put the system to sleep.

When the orange light stop blinking and stays on, you can wake up your console and the shellcodes will be executed.

You should get the Linux kernel booted and an available console on the UART Titania. 