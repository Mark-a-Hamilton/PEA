# **Privilege‑Escalation‑Analyser (PEA)**  
A structured analysis engine for processing raw LinPEAS output and converting it into a clear, modular, vulnerability‑focused privilege‑escalation report.

PEA does **not** replace LinPEAS — it **extends** it.

LinPEAS is one of the most widely used Linux privilege‑escalation enumeration tools, and without LinPEAS this analyser would not exist.

👉 **LinPEAS Repository**  
(You will link this in your final README)

---

## **What PEA Does**

PEA takes raw, unstructured LinPEAS output and:

- extracts relevant sections using profile markers  
- processes each subsection through modular analysis engines  
- matches findings against a structured PrivEsc knowledge base  
- produces a clean Markdown report  
- aligns findings with Privilege‑Escalation‑Principles  
- provides remediation guidance where applicable  

This makes LinPEAS output:

- easier to understand  
- easier to navigate  
- easier to act upon  
- easier to learn from  

---

# 📘 **Documentation Overview**

### **📘 pea.md — (How PEA Works)[.\Docs\pea.md]**  
A practical guide explaining:

- how to run PEA  
- what input/output looks like  
- how the internal workflow operates  
- how modules and profiles interact  
- how to interpret the final report  

---

### **📘 profiles.md — Profiles & Structure**  
A technical breakdown of:

- how `lin-default.json` defines sections, markers, and subsections  
- how `lin-kb.json` defines vulnerabilities  
- naming conventions  
- alphabetical ordering rules  
- future expansion for `win-*` and `mac-*` profiles  

---

### **📘 modules.md — Analysis Modules**  
A developer‑focused overview describing:

- each analysis module  
- what subsection it processes  
- what data it extracts  
- how it interacts with the KB  
- how modules contribute to the final report  
- how to extend modules for WinPEAS or MacPEAS  

---

### **📘 Privilege‑Escalation‑Principles.md**  
A methodology guide explaining:

- how to evaluate findings  
- how to identify exploit paths  
- how to prioritise remediation  
- how to apply privilege‑escalation logic consistently  

---

### **📘 Installation (from Install.md)**  
The Privilege‑Escalation‑Analyser (PEA) is designed to be:

- portable  
- self‑contained  
- easy to install  

This section provides:

- recommended installation method  
- guidance for custom directory layouts  
- notes about module/profile placement  
- instructions for adding PEA to your system PATH  

---

# **Why PEA Exists**

LinPEAS produces a huge amount of valuable information — but it is raw, dense, and unstructured.

PEA exists to:

- reduce analysis time  
- highlight actionable findings  
- provide structured vulnerability intelligence  
- make privilege‑escalation enumeration easier to understand  
- support both learning and professional DFIR use  

---

# **Authors**

### **Mark A. A. Hamilton**  
Creator and primary developer of the Privilege‑Escalation‑Analyser (PEA).  
Responsible for:

- tool architecture  
- module design  
- PrivEsc methodology  
- documentation structure  
- project direction  

### **Microsoft Copilot**  
Provided structured technical assistance, documentation drafting, architectural reasoning, and refinement of explanatory material.  
Contributed to clarity, consistency, and professional presentation of the project’s documentation.

---

# **Disclaimer**

The Privilege‑Escalation‑Analyser (PEA) is intended solely for **educational and defensive security purposes**.

This tool must only be used:

- on systems you **own**  
- on systems where you have **explicit written permission**  
- within authorised learning platforms such as **TryHackMe**, **Hack The Box**, etc.

PEA exists to help users understand Privilege Escalation principles, improve defensive awareness, and strengthen system hardening practices.

A wider understanding of privilege escalation techniques enables organisations and individuals to better protect their platforms against malicious attacks.

The author and contributors accept no responsibility for misuse of this tool.

---

# **Acknowledgements**

Special thanks to the creators of **LinPEAS** and **PEASS‑NG**.  
Their work is foundational to Linux privilege‑escalation research and tooling.

---

## ✅ **Your next step**
If you want, I can now generate:

- **pea.md**  
- **modules.md**  
- **profiles.md**  
- **Install.md**  
- **Privilege‑Escalation‑Principles.md**  
- A **folder structure** for the repo  
- A **CV‑ready description** for your PEA project  

Just tell me which file you want next.
