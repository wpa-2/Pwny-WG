import logging
import os
import subprocess
import time
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class WireGuard(plugins.Plugin):
    __author__ = 'Your Name'
    __version__ = '1.2.0' # The Rsync Update
    __license__ = 'GPL3'
    __description__ = 'A plugin to automatically connect to a WireGuard VPN and sync handshakes using rsync.'

    def __init__(self):
        self.ready = False
        self.status = "Initializing"
        self.wg_config_path = "/tmp/wg0.conf"
        self.last_sync_time = 0
        # Sync every 10 minutes (600 seconds)
        self.sync_interval = 600

    def on_loaded(self):
        """
        Called when the plugin is loaded.
        """
        logging.info("[WireGuard] Rsync plugin loaded.")
        if not self.options or 'private_key' not in self.options:
            logging.error("[WireGuard] Configuration is missing. Please edit /etc/pwnagotchi/config.toml")
            return
        # Check for rsync dependency
        if not os.path.exists('/usr/bin/rsync'):
            logging.error("[WireGuard] rsync is not installed. Please run: sudo apt-get install rsync")
            return
        self.ready = True

    def on_ui_setup(self, ui):
        """
        This method is called when the UI is Displayed to add a new element.
        """
        ui.add_element('wg_status', LabeledValue(
            color=BLACK,
            label='WG:',
            value=self.status,
            position=(60, 0), # Position (X, Y) from top-left
            label_font=fonts.Small,
            text_font=fonts.Small
        ))

    def _connect(self, ui):
        """
        Builds the config and brings the WireGuard interface up.
        """
        logging.info("[WireGuard] Attempting to connect...")
        self.status = "Connecting"
        ui.set('wg_status', self.status)

        try:
            subprocess.run(["wg-quick", "down", self.wg_config_path], capture_output=True)
        except FileNotFoundError:
            logging.error("[WireGuard] `wg-quick` command not found.")
            self.status = "No wg-quick"
            ui.set('wg_status', self.status)
            return False

        conf = f"""
[Interface]
PrivateKey = {self.options['private_key']}
Address = {self.options['address']}
"""
        if 'dns' in self.options:
            conf += f"DNS = {self.options['dns']}\n"
            
        conf += f"""
[Peer]
PublicKey = {self.options['peer_public_key']}
Endpoint = {self.options['peer_endpoint']}
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepalive = 25
"""
        if 'preshared_key' in self.options:
            conf += f"PresharedKey = {self.options['preshared_key']}\n"

        try:
            with open(self.wg_config_path, "w") as f:
                f.write(conf)
            os.chmod(self.wg_config_path, 0o600)

            subprocess.run(["wg-quick", "up", self.wg_config_path], check=True, capture_output=True)
            self.status = "Up"
            ui.set('wg_status', self.status)
            logging.info("[WireGuard] Connection established.")
            return True

        except subprocess.CalledProcessError as e:
            self.status = "Error"
            ui.set('wg_status', self.status)
            logging.error(f"[WireGuard] Connection failed: {e}")
            if hasattr(e, 'stderr'):
                stderr_output = e.stderr.decode('utf-8').replace('\n', ' | ').strip()
                logging.error(f"[WireGuard] Stderr: {stderr_output}")
            return False

    def _sync_handshakes(self):
        """
        Uses rsync to sync the handshakes directory.
        """
        logging.info("[WireGuard] Starting handshake sync...")
        
        source_dir = '/home/pi/handshakes/'
        remote_dir = self.options['handshake_dir']
        server_user = self.options['server_user']
        server_ip = self.options['peer_endpoint'].split(':')[0]
        
        # Ensure the source directory exists
        if not os.path.exists(source_dir):
            logging.warning(f"[WireGuard] Source directory {source_dir} not found. Skipping sync.")
            return

        # The -e option specifies the SSH command to use, including options for non-interactive use.
        # The trailing slash on the source directory is important - it copies the contents.
        command = [
            "rsync",
            "-avz",
            "--delete",
            "-e", "ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null",
            source_dir,
            f"{server_user}@{server_ip}:{remote_dir}"
        ]
        
        try:
            subprocess.run(command, check=True, capture_output=True)
            logging.info("[WireGuard] Handshake sync successful.")
            self.last_sync_time = time.time()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logging.error(f"[WireGuard] Handshake sync failed: {e}")
            if hasattr(e, 'stderr'):
                stderr_output = e.stderr.decode('utf-8').replace('\n', ' | ').strip()
                logging.error(f"[WireGuard] Stderr: {stderr_output}")

    def on_internet_available(self, agent):
        """
        Called when internet is available.
        """
        ui = agent.view()
        
        # First, connect if not already connected
        if self.ready and self.status not in ["Up", "Connecting"]:
            self._connect(ui)
        
        # Then, check if it's time to sync
        if self.ready and self.status == "Up":
            now = time.time()
            if now - self.last_sync_time > self.sync_interval:
                self._sync_handshakes()

    def on_unload(self, ui):
        """
        Called when the plugin is unloaded.
        """
        logging.info("[WireGuard] Unloading plugin and disconnecting.")
        if os.path.exists(self.wg_config_path):
            try:
                subprocess.run(["wg-quick", "down", self.wg_config_path], check=True, capture_output=True)
                os.remove(self.wg_config_path)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.error(f"[WireGuard] Failed to disconnect: {e}")
        
        with ui._lock:
            try:
                ui.remove_element('wg_status')
            except KeyError:
                pass