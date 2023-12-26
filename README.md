# EDRSilencer
Inspired by the closed source FireBlock tool [FireBlock](https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/) from MdSec NightHawk, I decided to create my own version and this tool was created with the aim of blocking the outbound traffic of running EDR processes using Windows Filtering Platform (WFP) APIs.

This tool offers the following features:
- Search known running EDR processes and add WFP filter to block its outbound traffic
- Add WFP filter for a specific process
- Remove all WFP filters created by this tool
- Remove a specific WFP filter by filter id
- Support to run in C2 with in-memory PE execution module (e.g., `BruteRatel's memexec`)

**The current EDR process block list (edrProcess) includes only a limited number of EDR solutions (e.g., MDE, Elastic EDR). It would be appreciated if someone could assist in expanding the process list in `EDRSilencer.c` to encompass a broader range of other EDR solutions.**

## Testing Environment
Tested in Windows 10 and Windows Server 2016

## Usage
```
Usage: EDRSilencer.exe <blockedr/block/unblockall/unblock>
- Add WFP filters to block the IPv4 and IPv6 outbound traffic of all detected EDR processes:
  EDRSilencer.exe blockedr

- Add WFP filters to block the IPv4 and IPv6 outbound traffic of a specific process (full path is required):
  EDRSilencer.exe block "C:\Windows\System32\curl.exe"

- Remove all WFP filters applied by this tool:
  EDRSilencer.exe unblockall

- Remove a specific WFP filter based on filter id:
  EDRSilencer.exe unblock <filter id>
```

## Compile
```
x86_64-w64-mingw32-gcc EDRSilencer.c -o EDRSilencer.exe -lfwpuclnt utils.c
```

## Example
### Detect and block the outbound traffic of running EDR processes
```
EDRSilencer.exe blockedr
```
![HowTo](https://github.com/netero1010/EDRSilencer/raw/main/example.png)

## Credits
https://www.mdsec.co.uk/2023/09/nighthawk-0-2-6-three-wise-monkeys/