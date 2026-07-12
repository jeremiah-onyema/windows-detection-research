# secedit writes to the Run key through services.exe, and default rules miss it

I wanted to see whether the rules people actually run catch behavior or just tool names. The idea that you shouldn't key on reg.exe or powershell.exe has been around since at least 2019. It's not new. But knowing an idea and having it in your deployed ruleset are two different things, so I went looking for a technique where the tool name lies about who did the work.

secedit was a good one to try. It's a built-in Windows tool for applying security templates, and Atomic Red Team has a test for it (T1547.001 Test 16). The test drops a small template that sets `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\calc` to `calc.exe`, then applies it with `secedit /configure`. I ran it, and the value landed. I could see it sitting in the registry. Then I looked at who wrote it.

In Sysmon Event 13, the process that made the write wasn't secedit, and it wasn't reg.exe. It was `C:\WINDOWS\system32\services.exe`, running as SYSTEM. services.exe is the Service Control Manager. secedit doesn't touch the registry itself when it applies the template. The write goes through the SCM, so services.exe is what shows up as the writer, and secedit never appears. That's the whole thing, and it's the reason it's worth catching. Rename the tool, script it differently, it doesn't matter. The write still comes from services.exe. The raw alert is [in the repo](../evidence/T1547.001/secedit_services_exe_run_key.json).

My Wazuh rule for reg.exe writing a Run key is 92302, and it stayed silent. Nothing fired. When I went to look at why, it was plain enough. 92302 keys on reg.exe:

```xml
<field name="win.eventdata.image" type="pcre2">(?i)reg\.exe</field>
```

The writer was services.exe, so it never matched. There's a base rule underneath it, 92300, that matches any process writing to a Run key, but it sits at level 0, which in Wazuh means it gets evaluated and never alerts on its own. The rules that actually raise an alert are its children: 92301 if the value ends in .lnk, .vbs or .vba, 92302 if the writer is reg.exe, 92303 if the value points at a known remote access tool. An .exe written by services.exe matches none of them, so Wazuh sees the write and stays quiet. The public Sigma rules for this technique do the same thing. reg.exe, powershell.exe, regedit.exe. Tool names.

There's a second half to this that's worse. If your stack is EDR-only and you don't forward Windows logs to a SIEM, there's nothing to catch this at all. services.exe writing to the registry is just Windows being Windows. The SCM touches the registry all day, and an EDR has no reason to flag it. And if you run Sysmon but its events never reach your SIEM, nobody sees the write either. The persistence just sits there. So this isn't hard to detect because it's clever. It's hard to detect because the one process you'd want to watch is a trusted system process doing something it does constantly, and because the telemetry that would show it often isn't where anyone's looking.

The fix is the old idea. Watch the behavior, not the tool. A process wrote an executable value to a Run key, and it wasn't one of the tools you'd expect to do that, like reg.exe, msiexec, or an installer. That's the rule. It doesn't care what the tool is called. services.exe writing calc.exe to a Run key matches it, and so does anything else that hands its write off the same way. The [Sigma rule](../sigma/persistence/T1547.001_registry_run_key/T1547001_secedit_services_run_key.yml) and the Wazuh version, rule 100013 in [local_rules.xml](../wazuh-rules/local_rules.xml), are both in the repo.

None of this is free. services.exe writes to the registry constantly as part of normal service management, so a rule watching it has to be scoped tight: Run keys specifically, an executable value, and a writer that isn't a known installer. Even then, baseline what legitimate software on your environment installs before you turn it up, or you'll get noise from software that sets up persistence the normal way. I'd run it at a low severity first and watch what it catches.

The idea that you shouldn't detect on tool names is old. The gap is that the default rules still do. This is one technique where you can see it plainly. The tool name in the rule and the process in the telemetry are two different things, and the rule loses.
