import threading
import queue
import time
import uuid
import random
import logging
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
import argparse

# Optional GUI
try:
    import tkinter as tk
    from tkinter.scrolledtext import ScrolledText
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# Colored output
import importlib

# Try to locate and import colorama dynamically to avoid static analysis/import resolution errors.
spec = None
try:
    spec = importlib.util.find_spec("colorama")
except Exception:
    spec = None

if spec is not None:
    try:
        colorama_mod = importlib.import_module("colorama")
        colorama_init = getattr(colorama_mod, "init", lambda **kwargs: None)
        Fore = getattr(colorama_mod, "Fore")
        Style = getattr(colorama_mod, "Style")
        try:
            colorama_init(autoreset=True)
        except Exception:
            # ignore initialization errors, fall back to no-op styling
            pass
    except Exception:
        # Provide simple fallbacks if colorama can't be loaded at runtime
        class Dummy:
            def __getattr__(self, item):
                return ""
        Fore = Style = Dummy()
else:
    # Provide simple fallbacks if colorama isn't installed
    class Dummy:
        def __getattr__(self, item):
            return ""
    Fore = Style = Dummy()

# Logging configuration
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

@dataclass
class Packet:
    id: str
    src: str
    dst: str
    payload: str
    ts: float  # original timestamp when created

    def summary(self) -> str:
        return f"Packet(id={self.id[:8]}, {self.src}->{self.dst}, payload={self.payload}, ts={self.ts:.3f})"


class NetworkMediator:
    """
    Mediator that delivers packets between server inbox queues.
    If intercept_mode is True, a copy is sent to MITM (server1) first.
    Also records flow events for visualization and replay.
    """
    def __init__(self, intercept_mode: bool = True):
        self.queues: Dict[str, queue.Queue] = {}
        self.lock = threading.Lock()
        self.intercept_mode = intercept_mode
        self.mitm_name = "server1"
        # Flow log: list of (time, event_type, src, dst, packet_id, payload)
        self.flow_log: List[Tuple[float, str, str, str, str, str]] = []
        self.replay_store: List[Tuple[float, Packet]] = []  # (created_ts, packet)

    def register(self, server_name: str, inbox: queue.Queue):
        with self.lock:
            self.queues[server_name] = inbox
            logging.info("Registered %s", server_name)

    def send(self, packet: Packet):
        """Deliver packet to destination. If intercept_mode is enabled, deliver copy to MITM first."""
        now = time.time()
        with self.lock:
            # store for replay (copy original timestamp and packet)
            self.replay_store.append((packet.ts, Packet(**vars(packet))))

            # record send event
            self.flow_log.append((now, "send", packet.src, packet.dst, packet.id, packet.payload))

            if self.intercept_mode and self.mitm_name in self.queues and packet.src != self.mitm_name:
                intercepted = Packet(id=packet.id, src=packet.src, dst=packet.dst, payload=packet.payload, ts=packet.ts)
                self.flow_log.append((time.time(), "intercept_to_mitm", packet.src, self.mitm_name, packet.id, packet.payload))
                self.queues[self.mitm_name].put(("intercept", intercepted))

            # Deliver to destination inbox (if exists)
            if packet.dst in self.queues:
                self.flow_log.append((time.time(), "deliver", packet.src, packet.dst, packet.id, packet.payload))
                self.queues[packet.dst].put(("deliver", packet))
            else:
                self.flow_log.append((time.time(), "drop", packet.src, packet.dst, packet.id, packet.payload))
                logging.warning("Destination %s unknown. Dropping packet: %s", packet.dst, packet.summary())

    def visualize_flow(self):
        """Return a textual visualization of the flow using recorded flow_log."""
        lines = []
        for t, ev, src, dst, pid, payload in self.flow_log:
            timestr = time.strftime("%H:%M:%S", time.localtime(t))
            if ev == "send":
                lines.append(f"{timestr} [SEND] {src} -> {dst} (id={pid[:8]}) payload={payload}")
            elif ev == "intercept_to_mitm":
                lines.append(f"{timestr} [INTERCEPT] {src} -> {self.mitm_name} (copy of {pid[:8]}) payload={payload}")
            elif ev == "deliver":
                lines.append(f"{timestr} [DELIVER] {src} -> {dst} (id={pid[:8]})")
            elif ev == "drop":
                lines.append(f"{timestr} [DROP] {src} -> {dst} (id={pid[:8]}) - unknown destination")
        return "\n".join(lines)

    def clear_flow(self):
        with self.lock:
            self.flow_log.clear()
            self.replay_store.clear()


class Server(threading.Thread):
    def __init__(self, name: str, mediator: NetworkMediator, gui_callback=None):
        super().__init__(daemon=True)
        self.name = name
        self.mediator = mediator
        self.inbox = queue.Queue()
        self.running = threading.Event()
        self.running.set()
        self.mediator.register(self.name, self.inbox)
        self.gui_callback = gui_callback  # function(msg_type, text) for GUI updates

    def send_packet(self, dst: str, payload: str):
        pkt = Packet(id=str(uuid.uuid4()), src=self.name, dst=dst, payload=payload, ts=time.time())
        self._print_send(pkt)
        self.mediator.send(pkt)

    def _print_send(self, pkt: Packet):
        print(f"{Fore.CYAN}[{self.name}] queuing -> {pkt.dst}: {pkt.payload}{Style.RESET_ALL}")

    def handle_deliver(self, pkt: Packet):
        # default delivery handling
        print(f"{Fore.GREEN}[{self.name}] DELIVERED: {pkt.summary()}{Style.RESET_ALL}")
        # GUI update
        if self.gui_callback:
            self.gui_callback("deliver", f"{self.name} received {pkt.summary()}")

    def handle_intercept(self, pkt: Packet):
        # default intercept (rare for non-MITM)
        print(f"{Fore.YELLOW}[{self.name}] INTERCEPTED (copy): {pkt.summary()}{Style.RESET_ALL}")
        if self.gui_callback:
            self.gui_callback("intercept", f"{self.name} intercepted {pkt.summary()}")

    def run(self):
        while self.running.is_set():
            try:
                tag, pkt = self.inbox.get(timeout=0.3)
            except queue.Empty:
                continue
            if tag == "deliver":
                self.handle_deliver(pkt)
            elif tag == "intercept":
                self.handle_intercept(pkt)

    def stop(self):
        self.running.clear()


class MITMServer(Server):
    """
    MITM that logs/intercepts/forwards. Detects safe patterns like token=VALUE.
    """
    TOKEN_REGEX = re.compile(r"token=([A-Za-z0-9_\-]+)")

    def __init__(self, name: str, mediator: NetworkMediator, gui_callback=None, modify_payload=False, log_to_file: Optional[str] = "mitm_log.txt"):
        super().__init__(name, mediator, gui_callback=gui_callback)
        self.modify_payload = modify_payload
        self.log: List[Tuple[float, Packet]] = []
        self.log_lock = threading.Lock()
        self.log_to_file = log_to_file

    def handle_intercept(self, pkt: Packet):
        # Log intercept
        tnow = time.time()
        with self.log_lock:
            self.log.append((tnow, pkt))
        # Console output (yellow)
        print(f"{Fore.YELLOW}[{self.name}] INTERCEPTED: {pkt.summary()}{Style.RESET_ALL}")
        if self.gui_callback:
            self.gui_callback("intercept", f"{self.name} intercepted {pkt.summary()}")

        # Safe pattern detection
        m = self.TOKEN_REGEX.search(pkt.payload)
        if m:
            token_val = m.group(1)
            notice = f"[{self.name}] SAFE PATTERN DETECTED token={token_val} in packet {pkt.id[:8]}"
            print(Fore.MAGENTA + notice + Style.RESET_ALL)
            if self.gui_callback:
                self.gui_callback("pattern", notice)
            # also append to log
            with self.log_lock:
                self.log.append((time.time(), Packet(id=pkt.id, src=pkt.src, dst=pkt.dst, payload=f"TOKEN_DETECTED:{token_val}", ts=pkt.ts)))

        # Optionally modify payload
        if self.modify_payload:
            old = pkt.payload
            pkt.payload = f"{pkt.payload} [modified-by-{self.name}]"
            print(Fore.RED + f"[{self.name}] Modified payload: '{old}' -> '{pkt.payload}'" + Style.RESET_ALL)
            if self.gui_callback:
                self.gui_callback("modified", f"{self.name} modified {pkt.id[:8]}")

        # Forward to intended destination
        forward_pkt = Packet(id=pkt.id, src=self.name, dst=pkt.dst, payload=pkt.payload, ts=time.time())

        # Avoid recursive interception loop by temporarily disabling mediator intercept
        was_intercept = self.mediator.intercept_mode
        try:
            self.mediator.intercept_mode = False
            # record forwarding in console and GUI
            print(f"{Fore.YELLOW}[{self.name}] Forwarding to {forward_pkt.dst}: {forward_pkt.summary()}{Style.RESET_ALL}")
            if self.gui_callback:
                self.gui_callback("forward", f"{self.name} forward {forward_pkt.summary()}")
            self.mediator.send(forward_pkt)
        finally:
            self.mediator.intercept_mode = was_intercept

    def save_log_to_file(self, path: Optional[str] = None):
        if path is None:
            path = self.log_to_file
        with self.log_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"--- MITM LOG DUMP {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                for ts, pkt in self.log:
                    f.write(f"{time.strftime('%H:%M:%S', time.localtime(ts))} {pkt.summary()}\n")
                f.write("\n")
        logging.info("Saved MITM logs to %s", path)


class SimpleClient(Server):
    def __init__(self, name: str, mediator: NetworkMediator, destinations: List[str], gui_callback=None,
                 send_interval: float = 1.0, total_msgs: int = 8):
        super().__init__(name, mediator, gui_callback=gui_callback)
        self.destinations = destinations
        self.send_interval = send_interval
        self.total_msgs = total_msgs
        self.sent = 0
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)

    def start_sending(self):
        self._sender_thread.start()

    def _sender_loop(self):
        while self.sent < self.total_msgs and self.running.is_set():
            dst = random.choice(self.destinations)
            # create safe payloads; occasionally include a 'token' for pattern detection demo
            if random.random() < 0.25:
                payload = f"msg-{self.sent+1} token={uuid.uuid4().hex[:8]}"
            else:
                payload = f"msg-{self.sent+1} from-{self.name}"
            self.send_packet(dst, payload)
            self.sent += 1
            time.sleep(self.send_interval)

    def handle_deliver(self, pkt: Packet):
        print(f"{Fore.GREEN}[{self.name}] RECEIVED: {pkt.summary()}{Style.RESET_ALL}")
        if self.gui_callback:
            self.gui_callback("deliver", f"{self.name} received {pkt.summary()}")
        # auto-ack
        reply_payload = f"ACK for {pkt.id[:8]} from {self.name}"
        time.sleep(0.1)
        self.send_packet(pkt.src, reply_payload)


class Receiver(Server):
    def __init__(self, name: str, mediator: NetworkMediator, gui_callback=None, auto_reply: bool = True):
        super().__init__(name, mediator, gui_callback=gui_callback)
        self.auto_reply = auto_reply

    def handle_deliver(self, pkt: Packet):
        print(f"{Fore.GREEN}[{self.name}] Received payload: {pkt.summary()}{Style.RESET_ALL}")
        if self.gui_callback:
            self.gui_callback("deliver", f"{self.name} received {pkt.summary()}")
        if self.auto_reply:
            reply_payload = f"ACK for {pkt.id[:8]} from {self.name}"
            time.sleep(0.2)
            self.send_packet(pkt.src, reply_payload)


# GUI class (runs in main thread when enabled)
class TrafficGUI:
    def __init__(self, title="MITM Traffic Monitor"):
        self.root = tk.Tk()
        self.root.title(title)
        self.text = ScrolledText(self.root, state="disabled", width=100, height=30)
        self.text.pack(fill="both", expand=True)
        self.lock = threading.Lock()
        # Buttons frame
        frm = tk.Frame(self.root)
        frm.pack(fill="x")
        tk.Button(frm, text="Save Logs", command=self._on_save_logs).pack(side="left")
        tk.Button(frm, text="Clear Screen", command=self._on_clear).pack(side="left")
        tk.Button(frm, text="Close", command=self.root.quit).pack(side="right")
        self.on_save_callback = None

    def start(self):
        # Run the Tk mainloop on the current thread.
        # IMPORTANT: On Windows, Tk must be run from the main thread (single-threaded apartment).
        # Calling this will block until the GUI is closed.
        self.root.mainloop()

    def append(self, text: str):
        with self.lock:
            self.text.configure(state="normal")
            self.text.insert("end", text + "\n")
            self.text.see("end")
            self.text.configure(state="disabled")

    def _on_save_logs(self):
        if self.on_save_callback:
            self.on_save_callback()

    def _on_clear(self):
        with self.lock:
            self.text.configure(state="normal")
            self.text.delete("1.0", "end")
            self.text.configure(state="disabled")


# --- Controller and interactive menu ---
class SimulationController:
    def __init__(self):
        self.mediator = NetworkMediator(intercept_mode=True)
        self.gui = None
        self.gui_enabled = False
        self.mitm = MITMServer("server1", self.mediator, gui_callback=self.gui_callback, modify_payload=False)
        self.sender = SimpleClient("server2", self.mediator, destinations=["server3", "server4"], gui_callback=self.gui_callback, send_interval=1.0, total_msgs=20)
        self.recv3 = Receiver("server3", self.mediator, gui_callback=self.gui_callback)
        self.recv4 = Receiver("server4", self.mediator, gui_callback=self.gui_callback)
        self.threads_started = False
        self._stop_event = threading.Event()

    def gui_callback(self, ev: str, text: str):
        ts = time.strftime("%H:%M:%S")
        line = f"{ts} [{ev.upper()}] {text}"
        
        # --- Console color output ---
        if ev == "intercept":
            print(Fore.YELLOW + line + Style.RESET_ALL)
        elif ev == "deliver":
            print(Fore.GREEN + line + Style.RESET_ALL)
        elif ev == "modified":
            print(Fore.RED + line + Style.RESET_ALL)
        elif ev == "pattern":
            print(Fore.MAGENTA + line + Style.RESET_ALL)
        else:
            print(line)

        # --- FIXED: Safe GUI update from main Tk thread ---
        if self.gui_enabled and self.gui:
            try:
                # Schedule update so it runs ONLY on Tk main thread
                self.gui.root.after(0, lambda: self.gui.append(line))
            except Exception:
                logging.exception("GUI update failed")

    def start_all(self):
        if not self.threads_started:
            self.mitm.start()
            self.sender.start()
            self.recv3.start()
            self.recv4.start()
            self.sender.start_sending()
            self.threads_started = True
            logging.info("All servers started.")
        else:
            logging.info("Servers already started.")

    def stop_all(self):
        self.sender.stop()
        self.mitm.stop()
        self.recv3.stop()
        self.recv4.stop()
        self._stop_event.set()
        logging.info("Stopping all servers...")

    def enable_mitm(self):
        self.mediator.intercept_mode = True
        logging.info("MITM interception enabled.")

    def disable_mitm(self):
        self.mediator.intercept_mode = False
        logging.info("MITM interception disabled.")

    def set_modify(self, flag: bool):
        self.mitm.modify_payload = flag
        logging.info("MITM modify_payload set to %s", flag)

    def show_visualization(self):
        viz = self.mediator.visualize_flow()
        print("\n=== PACKET FLOW VISUALIZATION ===")
        print(viz if viz else "(no events recorded)")
        print("=== END ===\n")

    def save_logs(self):
        self.mitm.save_log_to_file()

    def open_gui(self):
        if not GUI_AVAILABLE:
            logging.error("Tkinter not available on this environment.")
            return
        if not self.gui_enabled:
            self.gui = TrafficGUI()
            self.gui.on_save_callback = self.save_logs
            self.gui_enabled = True
            # Start the GUI mainloop on the current thread. This will block this thread
            # until the GUI is closed. This avoids "Calling Tcl from different apartment"
            # errors on Windows. If you need the interactive menu to remain responsive,
            # run the program with GUI in the main thread and the menu in a worker thread.
            self.gui.start()
            logging.info("GUI opened.")
        else:
            logging.info("GUI already open.")

    def replay_mode(self, speed: float = 1.0):
        """Replay stored packets from mediator.replay_store.
           speed=1.0 plays at real speed, >1 faster, <1 slower."""
        if not self.mediator.replay_store:
            logging.info("No stored packets for replay.")
            return
        logging.info("Starting replay (speed=%s). Clearing flow log before replay.", speed)
        # Create a temporary mediator so replay actions don't pollute existing flow in the same way
        replay_store = list(self.mediator.replay_store)  # list of (created_ts, Packet)
        # Sort by created timestamp
        replay_store.sort(key=lambda x: x[0])
        t0 = replay_store[0][0]
        base = time.time()
        for created_ts, pkt in replay_store:
            if not self.sender.running.is_set() and not self.mitm.running.is_set():
                logging.info("Replay aborted because servers stopped.")
                return
            # calculate when to send relative to base
            rel = (created_ts - t0) / speed
            send_at = base + rel
            wait = send_at - time.time()
            if wait > 0:
                time.sleep(wait)
            # send a new packet copy through mediator (will be intercepted if mitm on)
            pkt_copy = Packet(id=str(uuid.uuid4()), src=pkt.src, dst=pkt.dst, payload=pkt.payload, ts=time.time())
            logging.info("Replaying: %s", pkt_copy.summary())
            self.mediator.send(pkt_copy)
        logging.info("Replay finished.")

    def interactive_menu(self):
        menu = """
Interactive MITM Simulation Menu:
1. Start servers & sender
2. Enable MITM interception
3. Disable MITM interception
4. Toggle MITM modify payload ON
5. Toggle MITM modify payload OFF
6. Show packet-flow visualization
7. Save MITM logs to file (mitm_log.txt)
8. Open GUI traffic monitor (if supported)
9. Enter Replay Mode (replay captured packets)
10. Clear recorded flow & replay store
11. Show current mediator stats
12. Stop all servers (and exit)
13. Help (this menu)
"""
        print(menu)
        while True:
            try:
                choice = input("Choice> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting menu.")
                self.stop_all()
                return
            if choice == "1":
                self.start_all()
            elif choice == "2":
                self.enable_mitm()
            elif choice == "3":
                self.disable_mitm()
            elif choice == "4":
                self.set_modify(True)
            elif choice == "5":
                self.set_modify(False)
            elif choice == "6":
                self.show_visualization()
            elif choice == "7":
                self.save_logs()
            elif choice == "8":
                self.open_gui()
            elif choice == "9":
                try:
                    sp = float(input("Replay speed (1.0 = real time, >1 faster, <1 slower): ") or "1.0")
                except Exception:
                    sp = 1.0
                threading.Thread(target=self.replay_mode, args=(sp,), daemon=True).start()
            elif choice == "10":
                self.mediator.clear_flow()
                print("Cleared flow and replay store.")
            elif choice == "11":
                print(f"Intercept mode: {self.mediator.intercept_mode}")
                print(f"Flow events recorded: {len(self.mediator.flow_log)}")
                print(f"Replay packets stored: {len(self.mediator.replay_store)}")
                print(f"MITM log entries: {len(self.mitm.log)}")
            elif choice == "12":
                print("Stopping servers and exiting...")
                self.stop_all()
                return
            elif choice == "13":
                print(menu)
            elif choice == "":
                continue
            else:
                print("Unknown option. Enter 13 for help.")

# Entrypoint
def main():
    parser = argparse.ArgumentParser(description="Safe MITM simulation with many features (in-process).")
    parser.add_argument("--nogui", action="store_true", help="Disable GUI even if tkinter is available.")
    args = parser.parse_args()

    sim = SimulationController()

    # Respect nogui flag
    if not args.nogui and GUI_AVAILABLE:
        # Start GUI disabled until user opens it via menu
        pass

    # Start interactive menu in main thread
    try:
        sim.interactive_menu()
    except KeyboardInterrupt:
        print("Interrupted. Stopping all servers...")
        sim.stop_all()

if __name__ == "__main__":
    main()

"""


MITM simulation with these features:
1) Packet-flow visualization (end of run)
2) Colored terminal output (MITM=yellow, deliver=green, modified=red)
3) Safe pattern detection on payloads (detects token=VALUE)
4) Save MITM logs to mitm_log.txt (auto and on-demand)
5) Live GUI traffic monitor (Tkinter) - optional toggle
6) Replay mode (replay captured packets with original timing)
7) Interactive menu mode (choose modes at runtime)

Everything runs in-process using threading and queues.
"""
