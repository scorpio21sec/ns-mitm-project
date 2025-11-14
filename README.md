# 🛰️ MITM Traffic Simulator

### **A safe, in-process Man-In-The-Middle (MITM) simulation using Python threads, queues, GUI monitoring & packet replay**

This project provides a **fully safe**, **offline-only**, **in-process** simulation of network traffic involving multiple virtual servers communicating through a `NetworkMediator`.
A dedicated MITM server intercepts packets, detects token patterns, optionally modifies payloads, logs data, and forwards traffic.

It includes:
✔ Packet-flow visualization
✔ Colored terminal output
✔ Safe pattern detection (`token=VALUE`)
✔ GUI traffic monitor (Tkinter)
✔ Log saving & replay mode
✔ Interactive command menu
✔ Multi-threaded virtual servers

No real networking, no raw sockets — everything uses Python threads + queues.

---

# 🚀 Features

* 🧵 **Threaded servers** simulating network communication
* 📦 **Queue-based packet routing** via `NetworkMediator`
* 🕵️‍♂️ **MITM interception** with logging & pattern detection
* ✏️ Optional payload modification
* 📊 **Flow visualization** (SEND / INTERCEPT / DELIVER / DROP)
* 🪟 **Tkinter GUI** for real-time traffic logs
* 🔁 **Replay mode** (replays recorded packets)
* 🖍️ **Colored terminal output** using colorama (auto-fallback)
* 📜 **mitm_log.txt** auto-save
* 🎛️ **Interactive runtime menu**

---

# 📁 Project Structure

```
mitm_sim.py        # Main program with servers, mediator, MITM logic, replay, GUI, etc.
mitm_log.txt       # Auto-generated log file for MITM interceptions (optional)
README.md          # This file
```

---

# ▶️ Run the Program

### Normal mode:

```bash
python mitm_sim.py
```

### Disable GUI mode:

```bash
python mitm_sim.py --nogui
```

You will see an **interactive menu** with options to start servers, toggle MITM, visualize flow, open GUI, replay packets, etc.

---

# 📌 Interactive Menu Options

| Option | Action                                      |
| ------ | ------------------------------------------- |
| 1      | Start all servers and begin sending packets |
| 2      | Enable MITM interception                    |
| 3      | Disable MITM interception                   |
| 4      | Enable MITM payload modification            |
| 5      | Disable MITM payload modification           |
| 6      | Print packet-flow visualization             |
| 7      | Save MITM logs to file                      |
| 8      | Open GUI monitor                            |
| 9      | Replay captured packets                     |
| 10     | Clear flow & replay store                   |
| 11     | Show system stats                           |
| 12     | Stop everything and exit                    |
| 13     | Show help menu again                        |

---

# 🧠 Detailed Explanation of All Imported Libraries

Below is a complete explanation of every import used in your file.

---

## **Python Standard Library Imports**

### `threading`

Used to:

* Run servers concurrently (`Server`, `MITMServer`, `SimpleClient`, etc.)
* Control threads via events (`threading.Event`)
* Start background operations

**Why needed:** Each virtual server runs simultaneously like real network nodes.

---

### `queue`

Provides thread-safe `Queue()` used as **inboxes** for servers.

**Why needed:**
Simulates message passing between servers safely across threads.

---

### `time`

Used for:

* Timestamps in packets
* Waiting between sends
* Replay timing
* Logging readable times

---

### `uuid`

Generates unique packet IDs (`uuid.uuid4()`).

---

### `random`

Used by client to randomly pick:

* Which server to send to
* Whether to include a token in payload

---

### `logging`

Used for internal logs:

* server registration
* warnings
* replay info
* GUI errors

---

### `re`

Regular expressions used inside MITM for pattern detection:

```python
token=([A-Za-z0-9_\-]+)
```

---

### `sys`

Used internally for system-level operations (argparse, exit handling).

---

### `argparse`

Used for CLI arguments:

```
--nogui
```

Lets users disable GUI at startup.

---

### `dataclasses`

Used to define the `Packet` class cleanly:

```python
@dataclass
class Packet:
```

Gives auto-generated:

* `__init__`
* `__repr__`
* `__eq__`

---

### `typing`

Used for type hints:

* `Dict`
* `List`
* `Tuple`
* `Optional`

Improves readability and maintainability.

---

### `importlib`

Used for safely importing `colorama` dynamically.

This avoids startup crashes if colorama isn’t installed.

---

## **Optional GUI Library**

### `tkinter` and `ScrolledText`

Provides a real-time GUI window to display:

* intercepted packets
* deliveries
* patterns
* modifications

The GUI runs only when explicitly opened.

---

## **Optional External Library**

### `colorama`

Used for colorful console output:

* Yellow = MITM interception
* Green = delivery
* Red = modification
* Magenta = token detection

If not installed, the code automatically falls back to no-color mode.

---

# 🛰️ How the Simulation Works (High-Level)

### 1. **Servers**

`server2` sends messages
`server3` and `server4` receive and acknowledge
`server1` acts as MITM

---

### 2. **NetworkMediator**

Responsible for:

* Routing packets
* Copying packets to MITM
* Logging flow events
* Recording packets for replay

---

### 3. **MITMServer**

Intercepts traffic:

* Logs packets
* Detects tokens
* Optionally modifies payload
* Forwards modified packet
* Saves logs to file

---

### 4. **Replay Mode**

Your entire session's packets can be replayed with the same timing:

```python
speed = 1.0  # real time
speed = 2.0  # twice as fast
speed = 0.5  # slower motion
```

---

### 5. **GUI Monitor**

Shows:

* Deliveries
* Interceptions
* Detected patterns
* Modifications

Live scrolling window using Tkinter.

---





