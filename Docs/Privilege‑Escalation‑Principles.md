**[Return to README.md](../README.md)**

# **Privilege Escalation Principles**

The **Privilege‑Escalation‑Analyser (PEA)** provides a structured interpretation of LinPEAS output, enabling analysts to identify, validate, and remediate privilege‑escalation vectors with clarity and consistency.  
This document explains how to use the PEA output effectively and how to apply PrivEsc principles during investigation and hardening.

---

## **1. Preparation: Ensure the Target System Is Up‑to‑Date**

Before analysing privilege‑escalation vectors, ensure the target system is fully patched.  
This reduces noise in the LinPEAS output and prevents outdated vulnerabilities from appearing in the PEA report.

A fully updated system ensures:

- fewer false positives  
- shorter LinPEAS output  
- clearer PEA analysis  
- more accurate PrivEsc investigation  

---

## **2. Initial PEA Report Review**

After running PEA against the recovered LinPEAS output, begin by checking the report for structural issues:

### **a) Missing Modules**
If the report indicates a missing module:

- LinPEAS has evolved and introduced a new subsection, **or**  
- the profile does not map correctly to an existing module  

This is easily corrected by:

- adding a new module, or  
- updating the profile to include the missing subsection  

PEA is designed to surface these gaps so the tool can evolve alongside PEASS‑NG.

---

### **b) Missing Attack Vectors**
If an escalation entry is missing from the knowledge‑base profile:

- the KB requires an update  
- a new PrivEsc vector has been discovered  
- the vector is not yet mapped to remediation guidance  

These entries can be added manually or with the assistance of AI to ensure the knowledge base remains current.

After updating the KB, rerun PEA to validate the changes.

---

## **3. When No PEA Errors Are Present**

Once the report shows **no missing modules** and **no missing attack vectors**, the output is ready for full PrivEsc analysis.

At this stage, each vector can be:

- **assigned** for investigation  
- **validated** using controlled testing  
- **documented** with exploitation steps (for learning or DFIR)  
- **paired** with mitigation guidance  
- **tracked** through remediation  

This structured approach ensures every PrivEsc path is understood, tested, and closed.

---

## **4. Apply PrivEsc Principles During Investigation**

When analysing each vector, apply core PrivEsc principles:

- **Boundary Breaks**  
  Identify which privilege boundary is being bypassed (user → root, container → host, etc.).

- **Execution Hijacking**  
  Determine whether writable paths, services, or environment variables allow execution redirection.

- **Credential Exposure**  
  Check for leaked keys, passwords, tokens, or insecure storage.

- **Misconfiguration Exploitation**  
  Validate whether sudo rules, capabilities, or SUID binaries allow privilege elevation.

- **Kernel or Package Vulnerabilities**  
  Confirm whether outdated components expose known escalation paths.

These principles guide both exploitation testing and defensive remediation.

---

## **5. Final Validation: Rerun LinPEAS**

After remediation is complete:

1. Rerun LinPEAS on the target system  
2. Recover the new output  
3. Run PEA again  

The final PEA report should show:

- no remaining attack vectors  
- no missing modules  
- no missing KB entries  
- no exploitable PrivEsc paths  

This confirms that all identified escalation vectors have been successfully closed.

---

## **Summary**

The Privilege‑Escalation‑Principles document provides a structured method for interpreting PEA output and applying PrivEsc logic during investigation and hardening.  
By checking for missing modules, missing attack vectors, validating each escalation path, and rerunning LinPEAS after remediation, analysts can ensure systems are thoroughly assessed and secured.

PEA is designed to evolve alongside the PEASS‑NG project, ensuring long‑term relevance as new privilege‑escalation techniques emerge.

---
