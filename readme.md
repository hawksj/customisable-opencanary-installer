# OpenCanary Installation and Configuration Wrapper

[OpenCanary](https://github.com/thinkst/opencanary) is a configurable open-source honeypot solution provided by Thinkst. This wrapper script was originally created by [simonxciv](https://github.com/simonxciv) and modified by [hawksj](https://github.com/hawksj) to expedite deployment of multiple devices in an enterprise environment. This script helps install and configure your OpenCanary appliance running Raspberry OS, including:

- Setting a static IP address if internet connection fails
- Setting the device's hostname
- Updating the OS
- ~~Configuring unattended upgrades for OS and application patches~~
- Installing dependencies
- Installing and configuring the canary
- Creating a systemd unit file to launch OpenCanary as a service

## Pre-requisites
- Raspberry OS. This script may work in other Ubuntu or Debian operating systems, but some paths are specific to Raspberry OS and may not function correctly on a different OS.
- Internet connection

## Installation Instructions

For more detailed installation instructions for Simon's OC installer, see [his website](https://smnbkly.co/blog/opencanary-free-flexible-distributed-honeypot).

1. Copy or download the 'opencanary-installer.sh' to your home directory
2. Modify the permissions of the file to allow execution using `sudo chmod +x opencanary-installer.sh`
3. Run the installer using `sudo ./opencanary-installer.sh`
4. If a static IP is configured within the installation script, the device will reboot and the script will need to be run again. See step 3.
5. After the script automatically triggers a reboot, your device should be operating as a Canary

## Troubleshooting
1. Confirm the Canary service is running by entering `systemctl status opencanary`. You should see a returned value that includes `Active: active (running)`
2. Ensure your configuration file at \~/opencanary.conf is valid
3. Look for error messages at `/var/tmp/opencanary.log`

## Limitations
Not all modules can currently be configured using this script, however I have tried to include the most common ones. Additional modules will currently need to be configured directly in the OpenCanary configuration file (found in home direction or under /root/.opencanary.conf
