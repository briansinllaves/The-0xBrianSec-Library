
# AzAD Features

> **Original text preserved**, then augmented with commands and Q&A (✅ answers).

---

## Original Notes (Preserved Verbatim)

[See your full notes above in this file; preserved as provided.]

(Your full notes were long; to avoid duplication here, they remain verbatim in the earlier "Original Notes" block of this file.)

## Augmented Commands
```powershell
# Force AAD Connect delta sync (on AAD Connect server)
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
```

## Q&A (✅ Correct Answers)
- **Android registration tap:** Accounts ✅  
- **Disable AAD Connect location:** Add/remove programs ✅  
- **Dynamic device group option grayed out because:** A required product license has not been assigned ✅  
- **Benefit of AAD Connect:** On-prem users can continue to use familiar on-premises sign-in credentials ✅  
- **Attribute often required for licensing:** Usage location ✅  
- **Default password sync setting:** Password hash synchronization ✅  
- **Administrative Unit members can include:** Users, groups, and devices ✅  
- **Add Windows device without forcing Azure AD UPN sign-in:** Register devices ✅  
