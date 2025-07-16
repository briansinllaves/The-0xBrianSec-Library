Here's a nicely formatted version of your `tmux` notes:

---

### **tmux Cheat Sheet**

#### **Basic tmux Commands**

- **Start a New Session:**

  ```bash
  tmux new -s NMAP
  ```

  - Creates a new session ned `NMAP`.

- **Kill/Delete a Session:**

  ```bash
  tmux kill-session -t NMAP
  ```

  - Deletes the session ned `NMAP`.

- **Show All Sessions:**

  ```bash
  tmux list-sessions
  ```

  - Lists all active `tmux` sessions.

- **Attach to the Last Session:**

  ```bash
  tmux a
  ```

  - Attaches to the most recently used session.

- **Attach to a Specific Session:**

  ```bash
  tmux attach -t NMAP
  ```

  - Attaches to the session ned `NMAP`.

#### **Session Management**

- **Detach from Session:**

  - Press `Ctrl + b`, then `d`.

  - Detaches from the current session, leaving it running in the background.

- **Rene a Session:**

  - Press `Ctrl + b`, then `$`.

  - Allows you to rene the current session.

#### **Pane Management**

- **Split the Current Pane Vertically:**

  - Press `Ctrl + b`, then `%`.

  - Splits the active pane vertically.

- **Split the Current Pane Horizontally:**

  - Press `Ctrl + b`, then `"`.

  - Splits the active pane horizontally.

- **Close the Current Pane:**

  - Press `Ctrl + b`, then `x`.

  - Closes the active pane.

---

