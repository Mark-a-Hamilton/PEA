**[Return to README.md](../README.md)**

# **PEA Engine Overview**

Once installation is complete, running:

```bash
pea -h
```

will display the PEA help page, confirming that the analyser is correctly installed and available in your system PATH.

The PEA Engine transforms raw LinPEAS output into a structured, modular, and actionable privilege‑escalation analysis. This document outlines the workflow, processing pipeline, and the engine’s current capabilities.

---

## **Current Platform Support**

At present, the Privilege‑Escalation‑Analyser (PEA) is designed **specifically for LinPEAS output**.  
All profiles, modules, and knowledge‑base mappings are aligned with the structure and markers used by LinPEAS.

However, PEA’s architecture is intentionally built to be **platform‑agnostic**.  
This means future support for:

- **WinPEAS**  
- **MacPEAS**  
- **any future PEASS‑NG enumeration tools**

can be added without redesigning the engine.  
New profiles, modules, and knowledge‑base entries can be introduced as the PEASS project evolves.

---

## **Workflow Overview**

PEA integrates naturally into standard privilege‑escalation enumeration workflows.  
A typical investigation follows the sequence below:

### **1. Connect to the Target System**
Establish a secure session with the target host using SSH, RDP, or your preferred remote‑access method.

### **2. Upload LinPEAS**
Transfer the LinPEAS script to the target system using `scp`, `sftp`, or a platform‑specific file‑transfer mechanism.

### **3. Run LinPEAS and Capture Output**
Execute LinPEAS and redirect its output to a file:

```bash
./linpeas.sh > linpeas-output.lpe
```

This file becomes the input for PEA.

### **4. Recover the Output File**
Download the LinPEAS output file back to your analysis machine.  
All analysis is performed locally for security and consistency.

### **5. Clean Up the Target System**
Remove LinPEAS and any generated output files from the target host.  
Disconnect once the environment is restored.

### **6. Run PEA Against the LinPEAS Output**
Execute PEA locally:

```bash
pea -i linpeas-output.lpe
```

PEA will generate a structured analysis report containing:

- extracted sections  
- module‑driven findings  
- mapped privilege‑escalation indicators  
- remediation guidance  
- knowledge‑base references  

This report provides a clear, actionable interpretation of the raw LinPEAS data.

---

## **Engine Design Principles**

The PEA Engine is built around three core concepts:

### **1. Profiles**
Profiles define how LinPEAS output is segmented, interpreted, and mapped to analysis modules.  
They contain:

- section markers  
- subsection definitions  
- knowledge‑base references  
- PrivEsc principle mappings  

### **2. Modules**
Modules perform targeted analysis on specific subsections of LinPEAS output.  
Each module:

- extracts relevant data  
- evaluates conditions  
- matches findings against the knowledge base  
- contributes structured results to the final report  

### **3. Knowledge Base**
The KB provides contextual intelligence for:

- known privilege‑escalation vectors  
- misconfigurations  
- vulnerable states  
- exploitation paths  
- remediation guidance  

The engine combines these components to produce a consistent, repeatable analysis workflow.

---

## **Scalability and Future Evolution**

Although PEA currently supports **LinPEAS only**, its architecture is intentionally designed to be **scalable** and **extensible**.

As the PEASS‑NG project continues to evolve with:

- new LinPEAS checks  
- updated section markers  
- expanded enumeration logic  
- WinPEAS improvements  
- MacPEAS development  
- new platform‑specific privilege‑escalation tooling  

PEA can be extended by:

- adding new modules  
- creating new profiles (e.g., `win-default.json`, `mac-default.json`)  
- expanding the knowledge base  
- introducing platform‑specific engines (e.g., WinPEA, MacPEA)  

This ensures long‑term compatibility and provides a clear path for future development.

---

## **Reason for PEA project**

As I'm new to Privilege Escalation the LinPEAS output was overwhelming so I designed this tool to reduce the noise and turn the massive LinPEAS output file into a small concise detailed file extracting issues from the LinPEAS output file while expanding on the descriptions providing mitigation steps suitable for multiple audiences including Technical & non technical staff.

## **Summary**

The PEA Engine transforms raw LinPEAS output into a structured privilege‑escalation analysis using a modular, profile‑driven workflow.  
It supports defensive investigation, learning, and automation by providing clear, actionable insights into system misconfigurations and escalation vectors.

While PEA currently focuses on LinPEAS, its architecture is built to grow with the PEASS project, ensuring continued relevance as enumeration techniques evolve across Linux, Windows, macOS, and future platforms.

---
