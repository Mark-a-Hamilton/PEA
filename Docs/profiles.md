**[Return to README.md](../README.md)**

# **PEA Profiles Overview**

Profiles are the dynamic core of the **Privilege‑Escalation‑Analyser (PEA)**.  
They define how raw enumeration output is segmented, interpreted, and mapped to analysis modules and the knowledge base. Profiles allow PEA to adapt to different platforms, different enumeration tools, and the evolving structure of the PEASS‑NG project.

PEA currently supports **LinPEAS output only**, and all active profiles use the prefix:

```
lin-
```

This prefix identifies the profile as part of the **Linux Analysis Pack**, ensuring clarity when additional platform engines are introduced.

---

## **Profile Types**

Every PEA run uses **two profiles**, both of which are required:

### **1. The Default Profile (`lin-default.json`)**
Defines:

- section markers  
- subsection boundaries  
- module routing  
- PrivEsc principle mapping  

This profile determines *how* the LinPEAS output is broken down and which modules are responsible for analysing each part.

### **2. The Knowledge‑Base Profile (`lin-kb.json`)**
Defines:

- known privilege‑escalation vectors  
- misconfigurations  
- vulnerable states  
- exploitation paths  
- remediation guidance  

This profile provides contextual intelligence for the final report.

Together, these two profiles form the complete analytical definition for a PEA run.

---

## **Runtime Profile Selection**

Profiles can be overridden at runtime using the appropriate command‑line flags.  
This allows analysts to:

- test new profile definitions  
- use custom knowledge bases  
- adapt PEA to different environments  
- experiment with alternative section mappings  

Runtime selection ensures PEA remains flexible and suitable for both learning and professional DFIR workflows.

---

## **Platform Prefixes**

PEA uses profile prefixes to clearly distinguish platform‑specific logic.

### **Current Prefix**
```
lin-
```
Used for all Linux‑based profiles derived from LinPEAS output.

### **Future Prefixes**
As PEA expands to support additional PEASS‑NG tools, new prefixes will be introduced:

```
wpa-   # WinPEAS profiles
mac-   # MacPEAS profiles (future)
```

This naming strategy ensures:

- clean separation of platform logic  
- predictable profile routing  
- easy maintenance  
- straightforward expansion as enumeration tools evolve  

---

## **Dynamic Evolution of Profiles**

Profiles are intentionally designed to evolve over time.

If either:

- a **module entry** is missing from the default profile, or  
- an **escalation entry** is missing from the knowledge‑base profile  

PEA will **report the omission** in the final analysis output.

This behaviour ensures:

- transparency  
- maintainability  
- clear visibility of gaps  
- support for continuous improvement  

As new threats emerge and the PEASS‑NG project expands, profiles can be updated to reflect:

- new LinPEAS checks  
- new privilege‑escalation vectors  
- new misconfiguration patterns  
- new platform‑specific enumeration logic  

Profiles are the engine’s most adaptable component.

---

## **Summary**

Profiles define how PEA interprets enumeration output and how it maps findings to modules and the knowledge base.  
The current `lin-` profiles support LinPEAS output, while the architecture is ready for future `wpa-` and `mac-` profiles as WinPEAS, MacPEAS, and other PEASS‑NG tools evolve.

Their dynamic nature ensures PEA remains scalable, maintainable, and aligned with the ongoing development of privilege‑escalation enumeration techniques.

---
