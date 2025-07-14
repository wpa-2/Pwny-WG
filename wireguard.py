import logging
import os
import subprocess
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

class WireGuard(plugins.Plugin):
    __author__ = 'WPA2'
    __version__ = '1.2.0' # Final version with UI fixes
    __license__ = 'GPL3'
    __description__ = 'A plugin to automatically connect to a WireGuard VPN and upload handshakes.'

    def __init__(self):
        self.ready = False
        self.status = "Initializing"
        self.wg_config_path = "/tmp/wg0.conf"

    def on_loaded(self):
        """
        Called when the plugin is loaded.
        """
        logging.info("[WireGuard] Plugin loaded.")
        if not self.options or 'private_key' not in self.options:
            logging.error("[WireGuard] Configuration is missing. Please edit /etc/pwnagotchi/config.toml")
            return
        self.ready = True

    def on_ui_setup(self, ui):
        """
        This method is called when the UI is Displayed to add a new element.
        """
        # Add a LabeledValue element to the UI for the status
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
        ui.set('wg_status', self.status) # Force UI update

        try:
            # Defensively bring down the interface first to clear any stale state.
            subprocess.run(["wg-quick", "down", self.wg_config_path], capture_output=True)
        except FileNotFoundError:
            logging.error("[WireGuard] `wg-quick` command not found. Please run: sudo apt-get install wireguard-tools")
            self.status = "No wg-quick"
            ui.set('wg_status', self.status) # Force UI update
            return False

        # Build the configuration from the user's config.toml
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
            os.chmod(self.wg_config_path, 0o600) # Secure the config file

            # Bring the interface up
            subprocess.run(["wg-quick", "up", self.wg_config_path], check=True, capture_output=True)
            self.status = "Up"
            ui.set('wg_status', self.status) # Force UI update
            logging.info("[WireGuard] Connection established.")
            return True

        except subprocess.CalledProcessError as e:
            self.status = "Error"
            ui.set('wg_status', self.status) # Force UI update
            logging.error(f"[WireGuard] Connection failed: {e}")
            if hasattr(e, 'stderr'):
                # Format stderr to a single line to prevent log parsing errors
                stderr_output = e.stderr.decode('utf-8').replace('\n', ' | ').strip()
                logging.error(f"[WireGuard] Stderr: {stderr_output}")
            return False

    def on_internet_available(self, agent):
        """
        Called when internet is available. We use this to trigger the connection.
        """
        if self.ready and self.status not in ["Up", "Connecting"]:
            self._connect(agent.view())

    def on_handshake(self, agent, filename, access_point, client_station):
        """
        Called when a new handshake is captured.
        """
        if self.ready and self.status == "Up":
            logging.info(f"[WireGuard] New handshake captured. Uploading {filename}...")
            
            remote_path = os.path.join(self.options['handshake_dir'], os.path.basename(filename))
            server_user = self.options['server_user']
            server_ip = self.options['peer_endpoint'].split(':')[0]

            # For SCP to work without a password, SSH keys must be set up.
            command = ["scp", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null", filename, f"{server_user}@{server_ip}:{remote_path}"]
            
            try:
                subprocess.run(command, check=True, capture_output=True)
                logging.info(f"[WireGuard] Successfully uploaded handshake to {remote_path}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.error(f"[WireGuard] Handshake upload failed: {e}")
                if hasattr(e, 'stderr'):
                    stderr_output = e.stderr.decode('utf-8').replace('\n', ' | ').strip()
                    logging.error(f"[WireGuard] Stderr: {stderr_output}")

    def on_ui_update(self, ui):
        """
        Called when the UI is updated.
        """
        if self.ready:
            ui.set('wg_status', self.status)

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
        
        # This is the corrected block to remove the UI element
        with ui._lock:
            try:
                ui.remove_element('wg_status')
            except KeyError:
                pass