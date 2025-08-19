# Havoc C2 Quick Reference

## Overview

Havoc is a modern, open-source post-exploitation command and control (C2) framework. It supports custom profiles, encrypted comms, and flexible payloads.

---

## Setup

1. **Clone and Build Havoc**
    ```bash
    git clone https://github.com/HavocFramework/Havoc.git
    cd Havoc
    ./install.sh
    ```

2. **Start the Havoc Server**
    ```bash
    ./havoc server --profile profiles/havoc.yaotl --verbose --debug-dev
    ```
    - `--profile` specifies the comms/profile file (e.g., `profiles/havoc.yaotl`)
    - `--verbose` enables verbose output
    - `--debug-dev` enables developer debug output

3. **Start the Havoc Client (GUI)**
    ```bash
    ./havoc client
    ```

4. **Host Payloads (Optional)**
    - Use Python HTTP server to host payloads for download:
      ```bash
      python3 -m http.server 8080
      ```

---

## Profiles

- Profiles define how agents communicate (C2 channels, URIs, headers, etc.).
- Example: `profiles/havoc.yaotl`
- You can create or modify profiles to blend in with target network traffic.

---

## Payload Generation

1. **Generate a Payload**
    - In the Havoc client, go to the "Payloads" tab.
    - Select the desired profile and options (e.g., Windows, Linux, x64, stageless).
    - Click "Generate" and save the output.

2. **Deploy the Payload**
    - Deliver the payload to the target (phishing, USB drop, etc.).
    - For testing, run on a VM and connect back to your Havoc server.

---

## Listener/Connection

- By default, Havoc listens on `127.0.0.1` (localhost). Change in the profile for remote ops.
- Ensure firewall rules allow inbound connections on the chosen port.

---

## Useful Commands

- `help` — List available commands in the agent shell.
- `shell <cmd>` — Run a shell command on the target.
- `upload <file>` / `download <file>` — Transfer files.
- `screenshot` — Capture a screenshot from the target.
- `keylog_start` / `keylog_stop` — Start/stop keylogger.
- `persistence` — Attempt to establish persistence.

---

## Tips

- Always use unique profiles per engagement to avoid detection.
- Test payloads in a lab before deploying in production.
- Monitor logs for errors or failed connections.
- Use HTTPS and valid certificates for real-world operations.

---

## Resources

- [Havoc GitHub](https://github.com/HavocFramework/Havoc)
- [Official Documentation](https://havocframework.com/docs/)
- [Profile Examples](https://github.com/HavocFramework/Havoc/tree/main/profiles)

---
