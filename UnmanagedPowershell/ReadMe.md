# Unmanaged Powershell & How To Detect It
Powershell is one of the most powerful tools of any threat actor for post-exploitation tasks, and for this reason, it is very often used by threat actors after the exploitation. However, due to its power being known to security teams, it is usually closely monitored for any malicious or abnormal activity. For this reason, threat actors have been seen to utilize another technique to achieve two goals:
1.	Utilization of Powershell's set of tools for post-exploitation
2.	Evading the security rail guards put in place to detect Powershell abnormalities

This technique was first introduced by [@Ben0xA](https://twitter.com/Ben0xA) and later refined by others like [Lee Christensen](https://github.com/leechristensen/UnmanagedPowerShell) utilizes the Powershell's underlying libraries to use Powershell tools without ever opening the Powershell itself.
During my research on detecting unmanaged Powershell, there was a DLL that seemed to be used in both managed and unmanaged Powershell, and this DLL was called System.Management.Automation.
As an example, Blow Figure shows this DLL in a Powershell instance.
![alt text](https://github.com/n00blike/Security/blob/main/UnmanagedPowershell/Powershell.png)
After this finding, I looked for a way to detect this DLL in any image, and Sysmon Image Load (Event ID 7) was the answer:
```clojure
<RuleGroup name="" groupRelation="or">
<ImageLoad onmatch="include">
<ImageLoaded condition="contains">system.management.automation</ImageLoaded>	
</ImageLoad>
</RuleGroup>
```
The above config results in the generation of the log shown below:
![alt text](https://github.com/n00blike/Security/blob/main/UnmanagedPowershell/EventID%207.png)
It is also worth noting that this can result in quite a few false positives, and to mitigate those false positives, I suggest using Sysmon Process Creation (Event ID 1) and Hash whitelisting on processes that are loading System.Management.Automation.
