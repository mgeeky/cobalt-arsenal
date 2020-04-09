## cobalt-arsenal

My published set of Aggressor Scripts for Cobalt Strike 4.0+


- **`httprequest.cna`** - Safe & sound HTTP request implementation for Cobalt Strike 4.0 Aggressor Script. Works with HTTP & HTTPS, GET/POST/etc. + redirections. Rationale: I've tested various implementations of HTTP request sending subroutines written in Sleep for CS, but none of them matched by needs - working support for GET/POST, redirections handling and exceptions-safe execution. So I came up with my own implementation. ([gist](https://gist.github.com/mgeeky/2d7f8c2a6ffbfd23301e1e2de0312087)) 

- **`Payload_Variants_Generator.cna`** - This script generates stageless payload variants per each available architecture and output format type. Compatible with Cobalt Strike 4.0+.

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

