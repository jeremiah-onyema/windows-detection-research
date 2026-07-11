# Windows Detection Research

I want to understand what actually happens under the hood. Not just that an attack works, but why. What Windows does internally. What leaves a trace and what doesn't. What the OS was built to do versus what attackers make it do.

This lab is how I build that understanding.

I pick a technique, run it, and read every raw event it generates. Then I check what the default SIEM rules actually caught. Usually something interesting falls out of that.

## The finding that hooked me

The idea that you shouldn't detect on tool names has been around since at least 2019. Watch the behavior, not the binary. It's not new.

So I wanted to see whether the default rules people actually run today do that.

I used secedit to write a value to the Run key. Wazuh rule 92302 stayed silent. Nothing fired.

The write went through. I could see the value sitting in the registry. But the process that made the write wasn't secedit and it wasn't reg.exe. It was services.exe, running as SYSTEM. That's the Service Control Manager. secedit doesn't touch the registry itself; the write lands through the SCM, so secedit never shows up as the writer.

Rule 92302 only looks for reg.exe. The public Sigma rules I found for this technique do the same thing: reg.exe, powershell.exe, regedit.exe.

So the idea is old, but the default coverage still hasn't caught up to it.

There's a second half to this. If your team runs EDR and doesn't forward Windows logs to the SIEM, there's nothing to catch this at all. services.exe writing to the registry is just Windows being Windows, and the EDR has no reason to flag it. If Sysmon events never reach your SIEM, nobody sees the write either. The persistence just sits there.

That's the kind of thing I'm looking for.

## Current coverage

| Technique | Name | Key finding |
|-----------|------|-------------|
| T1027 | Obfuscated PowerShell (octal) | Script Block Logging captures the outer block but never the deobfuscated payload. A Windows limitation no rule can close. |
| T1053.005 | Scheduled Task Creation | taskContent is HTML-encoded in Wazuh, so raw regex breaks |
| T1546.003 | WMI Event Subscription | consumer and filter binding are catchable in Sysmon; default Wazuh misses them |
| T1547.001 | Registry Run Key Persistence | secedit writes through services.exe. Tool-based rules miss it, and EDR-only stacks never see it. |
| T1547.009 | Startup Folder Persistence | Olaf Hartong's sysmon-modular tags .lnk files as T1187, the wrong technique |
| T1071.004 | DNS C2 | dnscat2 uses raw UDP that skips the Windows DNS client, so there's nothing in event.dns.request |

More techniques in progress.

## What's in here

- `sigma/` - the rules, grouped by ATT&CK tactic and technique
- `evidence/` - the actual Wazuh alert each rule produced, pulled from the indexer and sanitized, so you can see what fired and which fields it keyed on
- `wazuh-rules/` - the local_rules.xml these run in

## Stack

Wazuh 4.14.3, Sysmon (Olaf Hartong config), LimaCharlie EDR, Atomic Red Team, Security Onion, Kali Linux, Windows 11, Ubuntu 24.04.

## About

Security Engineer at NinjaOne. My work is DFIR, threat hunting and purple teaming, and building detections comes out of that.

Most detection keys on the parts of an attack an attacker can change freely: a tool name, a hash, a path. So it breaks the moment they rename the binary. I look for the opposite. The one part of a technique that can't change without breaking the technique itself, and where that part shows up in the logs. Rename dnscat2 all you want, it still has to say where it's calling home. secedit still writes through services.exe no matter what you call it. I test that in the lab, build the rule around the part that can't move, and publish the raw evidence.

Sometimes the honest finding is that the thing you'd want to catch never gets logged at all. I write those up too.

[LinkedIn](https://linkedin.com/in/jeremiahonyema)
