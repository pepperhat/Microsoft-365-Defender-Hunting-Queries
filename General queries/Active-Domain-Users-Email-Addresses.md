# Active Domain Users' E-mail Addresses
This query returns a unique list of YOURDOMAIN email addresses for active domain users. For the purpooses of this query, an active domain user is defined as any AD user who has interactively logged into a machine, excluding  disabled accounts or possible shared Service Accounts. An accurate list of active user email addresses can be especially useful for importing into other applications, such as the Microsoft 365 Security Attack Simulator.

## Query
```
let usernames =
DeviceLogonEvents
| where LogonType in ("Interactive","CachedInteractive") and ActionType == "LogonSuccess"
| extend parsed = parse_json(AdditionalFields)
| extend Localcheck = tostring(parsed.IsLocalLogon)
| where Localcheck notcontains "false"
| where AccountDomain contains "YOURDOMAIN"
| summarize make_list(AccountName);
IdentityInfo
| where tolower(AccountName) in (usernames) 
| where IsAccountEnabled 
| where Department !in ( "ServiceAccounts")
| where tolower(EmailAddress) endswith "@YOURDOMAIN.com"
| summarize by EmailAddress
| sort by tolower(EmailAddress) asc 
```
## Sample output  
| EmailAddress | 
|:---------------:|
| asmith@yourdomain.com | 
| bsmith@yourdomain.com | 
| csmith@yourdomain.com | 
| dsmith@yourdomain.com | 

## Category
This query can be used to detect the following attack techniques and tactics ([see MITRE ATT&CK framework](https://attack.mitre.org/)) or security configuration states.
| Technique, tactic, or state | Covered? (v=yes) | Notes |
|------------------------|----------|-------|
| Initial access | v |  |
| Execution |  |  |
| Persistence |  |  | 
| Privilege escalation |  |  |
| Defense evasion |  |  | 
| Credential Access |  |  | 
| Discovery |  |  | 
| Lateral movement |  |  | 
| Collection |  |  | 
| Command and control |  |  | 
| Exfiltration |  |  | 
| Impact |  |  |
| Vulnerability |  |  |
| Misconfiguration |  |  |
| Malware, component |  |  |

## Contributor info
Contributor: Aaron M.
GitHub alias: pepperhat
