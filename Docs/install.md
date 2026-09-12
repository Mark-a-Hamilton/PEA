# **[Return to README.md](../README.md)**

# **Installation Guide**

The **Privilege‑Escalation‑Analyser (PEA)** is designed to be a lightweight, portable, and easy to install.  
The recommended installation method is a **global installation**, allowing the `pea` command to be executed from any directory.

This guide explains the preferred installation layout, environment configuration, and verification steps.

---

## **1. Recommended Global Installation Path**

A clean and predictable installation path ensures that PEA, its modules, and its profiles remain accessible across all shells and workflows.

A typical global installation location is:

```
/usr/local/bin/python
```

This directory is commonly used for user‑managed Python tooling and provides a stable location outside of system package managers.

---

## **2. Directory Structure**

Place the following items inside your chosen installation directory:

```
/usr/local/bin/python/
│
├── pea                 # Main PEA script
├── modules/            # Analysis modules
└── profiles/           # Profile definitions
```

> **Important:**  
> The `modules` and `profiles` directories **must** reside in the same directory as the `pea` script.  
> PEA uses relative paths to locate these components.

---

## **3. Add PEA to Your Shell PATH**

To make the `pea` command globally available, add the installation directory to your shell’s environment PATH.

For Bash:

```bash
export PATH="/usr/local/bin/python:$PATH"
```

For Zsh:

```zsh
export PATH="/usr/local/bin/python:$PATH"
```

You may place this line in your shell profile:

- `~/.bashrc`
- `~/.bash_profile`
- `~/.zshrc`

After updating the file, reload your shell profile:

```bash
source ~/.bashrc
```

(or the equivalent for your shell)

---

## **4. Verify Installation**

Once the PATH is updated and the profile reloaded, confirm that PEA is accessible:

```bash
pea -h
```

A successful installation will display the PEA help page, including usage instructions and available command options.

---

## **5. Notes for Custom Installations**

If you already use a structured tooling layout, you may install PEA in any preferred directory.  
However, the following rules always apply:

- The `pea` script, `modules/`, and `profiles/` **must remain together**  
- The directory containing `pea` **must be in your PATH**  
- The directory structure must not be altered unless you update the internal relative‑path logic

This ensures consistent behaviour across all environments.

---

## **Installation Complete**

You can now run PEA from any location and begin analysing LinPEAS output using your chosen profiles and modules.

---
