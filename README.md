# ps5-linux

**ps5-linux** leverages patched HV vulnerabilities to transform your **PS5 Phat and Slim** console running **3.00-7.61 firmwares** into a highly capable Linux PC, unlocking its full hardware potential for desktop use. Powered by 8 CPU cores (16 threads) at **3.5 GHz** and a GPU at **2.23 GHz**, it provides enough performance to run Steam games and various emulators with impressive fluidity.

Features:

- HDMI 4K60 video and audio output
- M.2 SSD as dedicated Linux partition
- All USB ports usable for peripherals
- BD drive usable via custom ahci driver
- Internal Bluetooth usable via custom xhci driver
- Ethernet port usable via custom gbe driver

![Alt Text](logo.webp)

## PS5 firmware

*ps5-linux* is only supported on PS5 Phat and Slim on the following firmwares:

- **3.00**, **3.10**, **3.20**, **3.21** without M.2 support
- **4.00**, **4.02**, **4.03**, **4.50**, **4.51** with M.2 support
- **5.00**, **5.02**, **5.10**, **5.50** with M.2 support
- **6.00**, **6.02** with M.2 support
- **7.20**, **7.61** with M.2 support

Support for 1.xx and 2.xx firmwares may be added in the future, but we will not prioritize this effort.

If you are on firmwares in-between or you want to update to a specific firmware, [download the correct PUP](https://darthsternie.net/ps5-firmwares/) and follow the [official guide](https://www.playstation.com/en-us/support/hardware/reinstall-playstation-system-software-safe-mode) to upgrade your PS5. **Obviously you cannot downgrade.**

## Hardwares

To run *ps5-linux*, you need some required and optional hardwares:

- **Required**: USB drive with minimum 64GB (ideally external SSD) to install and run Linux.
- **Required**: USB keyboard/mouse (dongles supported too).
- *Optional*: USB WLAN adapter for WLAN internet access.
- *Optional*: M.2 SSD compatible on PS5 (see [official guide](https://www.playstation.com/en-us/support/hardware/ps5-install-m2-ssd)) to run Linux from SSD.
- *Optional*: Bluetooth dongle to connect with PS5 DualSense controller.


## Configure PS5 settings

- **VERY IMPORTANT**: Enable Rest Mode features:
  - Go to `Settings` → `System` → `Power Saving` → `Features Available in Rest Mode` and set `Supply Power to USB Ports` to `Always`.
- **VERY IMPORTANT**: Disable HDMI Device Link:
  - Go to `Settings` → `HDMI` → `Enable HDMI Device Link`
- *Recommended*: Disable automatic updates:
  - Go to `Settings` → `System Software` → `System Software Update and Settings`
- *Recommended*: Disable automatic error reporting:
  - Go to `Settings` → `System Software` → `Report System Software Errors Automatically`

If you reset your PS5 settings or reinstall the FW, you need to reapply these settings again.

## Installation

### 1. Get a Linux image

#### Pre-built images

You can download them from [ps5-linux-image](https://github.com/ps5-linux/ps5-linux-image/releases/tag/latest). Recommended is `ps5-ubuntu2604.img.xz`. Unpack the `.xz` file.

#### Build your own image

If you use Windows,  run this in PowerShell or CMD as administrator to install WSL

```bash
wsl --install
```

Install docker:

```bash
sudo apt update
sudo apt install docker.io -y
sudo service docker start
sudo usermod -aG docker $USER
```

Then clone and build:

```bash
cd ~/
git clone https://github.com/ps5-linux/ps5-linux-image
cd ps5-linux-image
chmod +x ./build_image.sh
./build_image.sh --distro ubuntu2604
```

The finished image is written to `output/ps5-ubuntu2604.img`.

### 2. Flash the image to USB
Minimum drive size: 64 GB. An external SSD is strongly recommended.

#### Linux/macOS:

```bash
# check drive name with lsblk / diskutil list
sudo dd if=output/ps5-ubuntu2604.img of=/dev/sdX bs=4M status=progress conv=fsync
```

#### Windows (Balena Etcher):

Download [Balena Etcher](https://etcher.balena.io/), select the `.img` file, select your USB drive, click Flash.

### 3. Plug the USB drive into your PS5

The following USB ports are supported for booting:

- Front bottom Type-C port
- Rear Type-A ports

The front top Type-A port is USB 2.0 which is slower and thus not recommended.

### 4. Run the jailbreak

#### Firmware 3.00-5.50

1. Clone via: `git clone https://github.com/idlesauce/umtx2`
2. Configure fakedns via `dns.conf` to point `manuals.playstation.net` to your PCs IP address
3. Run fake dns: `sudo python fakedns.py -c dns.conf`
4. In a different terminal, run HTTPS server: `sudo python host.py`
5. Go into PS5 advanced network settings and set primary DNS to your PCs IP address and leave secondary at `0.0.0.0`
6. Go to user manual in settings and accept untrusted certificate prompt, run.

#### Firmware 6.00-7.61

1. Install Y2JB by following https://github.com/Gezine/Y2JB.
2. Run kernel exploit: `python3 payload_sender.py $PS5IP 50000 payloads/lapse.js`

### 5. Send the payload
If you're on ARM64 Linux, first install the x86-64 cross-compilation tools before:

```bash
sudo apt install gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu
```

Either download [ps5-linux-loader.elf](https://github.com/ps5-linux/ps5-linux-loader/releases/), or install [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) and compile it yourself:

```bash
git clone https://github.com/ps5-linux/ps5-linux-loader
cd ps5-linux-loader
make
```

Send the payload with your `$PS5IP` (shown on the page):

```bash
socat -t 99999999 - TCP:$PS5IP:9021 < ps5-linux-loader.elf
```

If all is successful, the payload will automatically go into rest mode. Wait until the orange LED stops blinking and becomes static. Only then, press the power button again to boot your PS5 into Linux. If the boot is successful, **the LED should turn white**. If it boots back into PS5 OS, then it's because you pressed the power button too early. Or, you did not enable rest mode features as described above. If it freezes instead of going into rest mode, then it is likely because you have etahen/kstuff enabled, which is incompatible. Disable them.

If the LED is white, but you still have a blackscreen then:

- Try removing `video=DP-1:1920x1080@60` line in cmdline.txt.
- Try setting HDCP on or off (try both).
- Try different monitors or capture cards, ideally with different resolutions. Currently, some monitors have issues.
- Try setting `amdgpu.force_1080p=1` in `cmdline.txt` in the FAT32 partition of the USB drive.

If none of this helps, please report the issue in our [Discord server](https://discord.gg/PeMGVB7BAm) and provide your EDID information.


## First Boot

Configure your system and memorize your login password.

Then, there are certain settings and commands we recommend doing:

1. Disable screen saver, as it is currently buggy.

2. Possibly, you have to disable and reenable your Wired/WLAN connection to get internet connection.

3. Hold packages to prevent updating the kernel when doing `apt upgrade`:
   ```bash
   sudo apt-mark hold linux-generic linux-generic-hwe-24.04 linux-generic-hwe-26.04 linux-image-generic linux-image-generic-hwe-24.04 linux-image-generic-hwe-26.04 linux-headers-generic linux-headers-generic-hwe-24.04 linux-headers-generic-hwe-26.04
   ```

4. Install Firefox:

   ```bash
   sudo snap install firefox
   ```

5. Update mesa:

   ```bash
   sudo snap refresh mesa-2404 --channel=latest/edge
   sudo add-apt-repository ppa:kisak/kisak-mesa
   sudo apt update
   sudo apt upgrade
   ```

6. Clone our [ps5-linux-tools](https://github.com/ps5-linux/ps5-linux-tools):

   ```bash
   sudo apt install zlib1g-dev
   git clone https://github.com/ps5-linux/ps5-linux-tools
   cd ps5-linux-tools
   make
   ```

7. If you have a Marvell WLAN chip (`lspci -nn` shows `40:00.7 Ethernet controller [0200]: Marvell Technology Group Ltd. Device [1b4b:2b56] (rev 02)`), then you can install the WLAN driver:

   ```bash
   git clone https://github.com/ps5-linux/ps5-linux-mwifiex
   cd ps5-linux-mwifiex
   sudo ./install.sh
   ```

## M.2 installation

You can use a M.2 SSD exclusively for Linux (which means you cannot use it for PS5 game storage).

1. Attach the M.2 SSD by following the [official guide](https://www.playstation.com/en-us/support/hardware/ps5-install-m2-ssd).
2. **VERY IMPORTANT**: If you used the M2. SSD for games before, reformat it on the PS5 under `Settings` → `Storage` → `M.2 SSD Storage`.
3. Boot Linux on your PS5 and run these commands to initialize your M.2:

```bash
cd ps5-linux-tools
sudo ./m2_init
```

4. Reboot via `sudo reboot`. If your PS5 asks you to format your M.2 again, please report this issue to us in our [Discord server](https://discord.gg/PeMGVB7BAm) and provide your M.2 model and storage size.
5. Relaunch Linux on your PS5.
6. Copy the `ps5-ubuntu2604.img` image that you built during installation or rebuild it on your PS5. Then, install it onto your M.2:

```bash
cd ps5-linux-tools
chmod +x ./m2_install.sh
sudo ./m2_install.sh --install $PATH_TO_YOUR_IMG
```

Now, you can boot into Linux on your M.2 via:

```bash
cd ps5-linux-tools
chmod +x ./m2_exec.sh
sudo ./m2_exec.sh
```

Then follow the same instructions again as the previous section.

In order to always boot Linux from your M.2, you can edit the label at `/boot/efi/cmdline.txt` from `root=LABEL=ubuntu2604` to `root=LABEL=ubuntu2604-m2`. You will still require a USB drive with the FAT32, but you can reformat the ext4 partition.

## Fan & boost control

We provide a simple tool that allows you to boost your CPU to 3500Mhz and GPU to 2230MHz as well as changing the fan curve:

```bash
cd ps5-linux-tools
sudo ./ps5_control --fan on
sudo ./ps5_control --boost on
```

Always turn on fan when your turn on boost, as this is what the official PS5 OS does.

## Updating ps5-linux

For any future ps5-linux updates, you can download the `.deb` or `.pkg.tar.zst` on your PS5 from [ps5-linux-patches](https://github.com/ps5-linux/ps5-linux-patches/releases) and install them like normal packages.

## FAQ

- Q: Will higher >=8.00 firmwares be supported?
  - A: No.
- Q: Why can I not use M.2 on 3.xx?
  - A: Because the PS5 fails to boot with it attached.
- Q: Can I dual-boot Linux and PS5 OS?
  - A: No, this is a soft-mod. You need to re-run the exploit in order to boot into Linux.
- Q: Can I put Linux into standby and resume?
  - A: No, this is not supported. We may however add a shutdown feature that puts your PS5 into rest-mode allowing you to relaunch Linux when powering up again.
- Q: Can I continue using my PS5 if I install Linux?
  - A: Yes, the internal SSD is not modified
- Q: Can I use the PS5's NIC/WLAN module in Linux?
  - A: WLAN is only supported for Marvell chipsets at the moment. Ethernet is supported on all models.
- Q: Does the DualSense controller work?
  - A: Yes, via internal Bluetooth as well as Bluetooth dongle.
- Q: What resolutions and refresh rates are supported?
  - A: 1080p, 1440p and 2160p at 60Hz are broadly supported. 1440p@120Hz has been the only confirmed working on the DELL S3225QC yet. 120Hz or 30Hz may be added in the future.
- Q: After reboot, I get a "Repairing" screen and "Your PS5 wasn't turned off properly." screen. Is that normal?
  - A: Yes, and it's harmless.

## Tips and tricks

- If you see graphical issues in your games, add the environment variable `RADV_DEBUG=nohiz` as [recommended for BC250](https://elektricm.github.io/amd-bc250-docs/drivers/environment/#critical-environment-variables) as well.
- You can adjust the kernel cmdline in `cmdline.txt` in the FAT32 partition.
- You can adjust the VRAM size in `vram.txt` in the FAT32 partition. By default, it uses 512MB (0x20000000) which enables [Dynamic VRAM allocation](https://elektricm.github.io/amd-bc250-docs/bios/flashing/#why-flash-the-bios).
- Monitor hotswap may work, but it will not change resolution automatically.
- Some monitors have a black screen if a video=DP-1: parameter is set in `cmdline.txt`. Confirmed working without `video=DP-1:1920x1080@60` on:
  - MSI MAG274Q QD E2, DELL S2721DGF, DELL U2515H (1440p@60Hz)
  - Possibly also: LG 27GL850, Lenovo Legion Y27q, ViewSonic Elite XG270QG

Many configurations, tips and tricks from the [AMD BC250 Documentation](https://elektricm.github.io/amd-bc250-docs/) also apply to PS5.

## Bugs

- screen save does not work properly
- hdmi audio output does not work on some monitors
- hdmi 1440p and 2160p video output does not work on some monitors

## Upstreamed changes

During this project, we have upstreamed some changes:

- [drm/amd: fix dcn 2.01 check](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/drivers/gpu/drm/amd/display/dc?id=39f44f54afa58661ecae9c27e15f5dbce2372892)
- [amd/addrlib: Add more GFX1013 GPUs](https://gitlab.freedesktop.org/mesa/mesa/-/commit/44bed00b8bbcb1825e2c920cf1a828efdc72b1f1)

## Discord

Join our [Discord server](https://discord.gg/PeMGVB7BAm) to celebrate Linux on PS5, receive help, learn tips & tricks, join development, or report issues.

## Credits

- [theflow](https://github.com/TheOfficialFloW): [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader), [ps5-linux-patches](https://github.com/ps5-linux/ps5-linux-patches), [ps5-linux-tools](https://github.com/ps5-linux/ps5-linux-tools)
- [c0w](https://github.com/c0w-ar): [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader)
- [resulknad](https://github.com/resulknad): [ps5-linux-image](https://github.com/ps5-linux/ps5-linux-image)
- [rmuxnet](https://github.com/rmuxnet): [ps5 ethernet driver](https://github.com/ps5-linux/ps5-linux-patches/commit/643e214d7bd37f292045fc0dbb821e421f7a3e47)
- [fail0verflow](https://github.com/fail0verflow): [prosperous](https://github.com/fail0verflow/prosperous)
- [flatz](https://github.com/flatz): [HV exploit](https://gist.github.com/flatz/620ddda6d64acca6d1c990dc3080ac0e)
- [cragson](https://github.com/cragson): [HV expoit implementation](https://github.com/cragson/ps5-hen)
- [john-tornblom](https://github.com/john-tornblom): [PS5 SDK](https://github.com/ps5-payload-dev/sdk)
- [echostretch](https://github.com/echostretch): Offsets and testing
- [kirathenotebook](https://github.com/kirathenotebook): Betatesting and readme contribution
- 15432: Tests on BC-250
