# WN10-CC-000050
# 🛡️ Vulnerability Management Lab – WN10-CC-000050

**Control Title:** Hardened UNC Paths Must Be Defined  
**STIG ID:** WN10-CC-000050  
**Compliance Frameworks:** DISA STIG, NIST 800-53 (AC-17, SC-12), HIPAA  
**Lab Stack:** Azure + Windows 10 + Tenable.sc/Nessus + PowerShell  
**Category:** File/Network Authentication Hardening  
**Remediation Method:** Registry Configuration

---

## 🎯 Lab Objective

Demonstrate how to simulate, detect, and remediate a vulnerability where **UNC path hardening** is not enforced for the `\\*\SYSVOL` and `\\*\NETLOGON` shares, violating security policies that require integrity and authentication for network paths.

---

## 📑 Table of Contents

1. [Azure VM Setup](#azure-vm-setup)  
2. [Vulnerability Implementation](#vulnerability-implementation)  
3. [Tenable Scan Configuration](#tenable-scan-configuration)  
4. [Initial Scan Results](#initial-scan-results)  
5. [Remediation via PowerShell](#remediation-via-powershell)  
6. [Verification Steps](#verification-steps)  
7. [Security Rationale](#security-rationale)  
8. [Post-Lab Cleanup](#post-lab-cleanup)  
9. [Appendix: PowerShell Commands](#appendix-powershell-commands)

---

## ☁️ Azure VM Setup

### 🔸 Parameters

| Setting              | Value                         |
|----------------------|-------------------------------|
| OS Image             | Windows 10 Pro (x64, Gen2)    |
| VM Size              | Standard D2s v3               |
| Resource Group       | `vm-lab-uncpath`              |
| Region               | Closest Azure region          |
| Admin Username       | Use **strong password** (avoid defaults like `labuser/Cyberlab123!`) |

### 🔸 Network Security Group (NSG)

- Allow **RDP (TCP 3389)** from your IP
- Optionally allow **WinRM (TCP 5985)** for scanning
- Block all other unnecessary inbound traffic

---

## 🔧 VM Configuration

### 🔹 Disable Windows Firewall

- Run `wf.msc` → Disable Domain, Private, and Public profiles

### 🔹 Enable Remote Registry / Credential Access

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force
```

📸 **Screenshot Placeholder:** `Screenshot_01_VM_Config.png`

---

## 💥 Vulnerability Implementation

### 🔸 Description

When UNC path hardening is not defined, Windows systems may allow unprotected access to critical file shares like `\\*\SYSVOL` and `\\*\NETLOGON`, making them vulnerable to **man-in-the-middle (MiTM)** attacks.

### 🔸 Simulate Non-Compliant State

```powershell
# Simulate vulnerability: UNC path hardening disabled (non-compliant)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "UNCPathBehavior" -Value 0
```

📸 **Screenshot Placeholder:** `Screenshot_02_UNCPath_Vulnerable.png`

---

## 🔍 Tenable Scan Configuration

### Template: **Advanced Network Scan**  
Audit File: **DISA Microsoft Windows 10 STIG**

### 🔹 Required Services

- Remote Registry
- Admin Shares (C$)
- Server Service

### 🔹 Discovery Settings

- Ping remote host
- TCP full port scan
- Windows authentication (local admin)

📸 **Screenshot Placeholder:** `Screenshot_03_Tenable_Scan_Setup.png`

---

## 🧪 Initial Scan Results

| STIG ID         | WN10-CC-000050 |
|------------------|----------------|
| Status           | ❌ Fail        |
| Plugin Output    | UNC path hardening not defined |
| Detected Value   | `UNCPathBehavior = 0` |
| Required Value   | `UNCPathBehavior = 3` |

📸 **Screenshot Placeholder:** `Screenshot_04_Scan_Results_FAIL.png`

---

## 🛠️ Remediation via PowerShell

### 🔸 Secure Configuration Fix

```powershell
# Enforce UNC path hardening for SYSVOL and NETLOGON
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "UNCPathBehavior" -Value 3
```

📸 **Screenshot Placeholder:** `Screenshot_05_UNCPath_Remediation.png`

> ℹ️ You may need to restart the system or restart services (e.g., `Workstation`) for the setting to fully apply.

---

## ✅ Verification Steps

### 1. Confirm Registry Setting

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "UNCPathBehavior"
```

**Expected Output:**
```
UNCPathBehavior : 3
```

📸 **Screenshot Placeholder:** `Screenshot_06_Verify_UNCPath_OK.png`

### 2. Re-Run Tenable Scan

| STIG ID         | Result |
|------------------|--------|
| WN10-CC-000050   | ✅ Pass |

📸 **Screenshot Placeholder:** `Screenshot_07_Scan_Results_PASS.png`

---

## 🔐 Security Rationale

UNC path hardening protects authentication and integrity of communication with critical Windows shares such as:

- `\\*\SYSVOL`
- `\\*\NETLOGON`

By requiring mutual authentication and message integrity, this setting mitigates risks like:

- **NTLM relay attacks**
- **SMB spoofing**
- **Unauthorized configuration modification**

### 🔒 Compliance Requirements

| Standard      | Control Reference                          |
|---------------|---------------------------------------------|
| **DISA STIG** | WN10-CC-000050                              |
| **NIST 800-53** | SC-12, AC-17, SI-7                        |
| **HIPAA**     | §164.312(c)(1) – Data Integrity             |
| **CMMC**      | SC.3.177 – Prevent unauthorized file shares |

---

## 🧼 Post-Lab Cleanup

1. 🔄 Restart the system to enforce policy (or restart `Workstation` service)
2. 🧹 Remove the resource group:
```bash
az group delete --name vm-lab-uncpath --yes --no-wait
```
3. 🧽 Clear saved credentials in Tenable

---

## 📎 Appendix: PowerShell Commands

| Task                  | Command |
|-----------------------|---------|
| Simulate Vulnerability| `Set-ItemProperty ... UNCPathBehavior -Value 0` |
| Remediate             | `Set-ItemProperty ... UNCPathBehavior -Value 3` |
| Verify                | `Get-ItemProperty ... UNCPathBehavior` |
| Enable Remote Access  | `Set-ItemProperty ... LocalAccountTokenFilterPolicy -Value 1` |

---

✅ **Lab Complete**

You've successfully simulated, detected, remediated, and verified **UNC path hardening enforcement** for `WN10-CC-000050` in a compliant Windows 10 lab environment using Azure and Tenable.

