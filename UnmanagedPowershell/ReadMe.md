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
Below is an splunk query that finds any process that has loaded the System.Management.Automation and it then correlates it with Event Code 1 to get the process information at the end of this query you can filter hashes by whitelisting to reduce false positives.
```clojure
index = * AND EventCode = 7 AND OriginalFileName="System.Management.Automation.dll" 
| table process_id,OriginalFileName,ImageLoaded,Image 
| join left=L right=R where L.process_id=R.ProcessId 
    [ search index = * AND EventCode = 1 
    | table LogonId,Image,SHA256,CommandLine,user,ProcessId] 
| rename R.ProcessId as ProcessID,L.OriginalFileName as DLL_Name,L.ImageLoaded as DLL_Path
,R.Image as Process_Path,R.LogonId as LogonID,R.SHA256 as Process_Hash,R.user as Running_User,R.CommandLine as CommandLine
| fields - L.*,R.*
```
