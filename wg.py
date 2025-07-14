import logging
import os
import subprocess
import pwnagotchi.plugins as plugins

class WireGuard(plugins.Plugin):
    __author__ = 'Your Name'
    __version__ = '1.0.0'
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

    def _connect(self):
        """
        Builds the config and brings the WireGuard interface up.
        """
        logging.info("[WireGuard] Attempting to connect...")
        self.status = "Connecting"
        
        # Build the WireGuard configuration from options
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
            self.status = "Connected"
            logging.info("[WireGuard] Connection established.")
            return True

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.status = "Error"
            logging.error(f"[WireGuard] Connection failed: {e}")
            if hasattr(e, 'stderr'):
                logging.error(f"[WireGuard] Stderr: {e.stderr.decode('utf-8').strip()}")
            return False

    def on_internet_available(self, agent):
        """
        Called when internet is available. We use this to trigger the connection.
        """
        if self.ready and self.status != "Connected":
            self._connect()

    def on_handshake(self, agent, filename, access_point, client_station):
        """
        Called when a new handshake is captured.
        """
        if self.ready and self.status == "Connected":
            logging.info(f"[WireGuard] New handshake captured. Uploading {filename}...")
            
            remote_path = os.path.join(self.options['handshake_dir'], os.path.basename(filename))
            server_user = self.options['server_user']
            # The server IP is the first part of the Endpoint, without the port
            server_ip = self.options['peer_endpoint'].split(':')[0]

            # For SCP to work without a password, SSH keys must be set up from the
            # Pwnagotchi's root user to the target server's user.
            command = [
                "scp",
                "-o", "StrictHostKeyChecking=no", # Avoids host key prompts
                "-o", "BatchMode=yes",          # Prevents password prompts
                filename,
                f"{server_user}@{server_ip}:{remote_path}"
            ]
            
            try:
                subprocess.run(command, check=True, capture_output=True)
                logging.info(f"[WireGuard] Successfully uploaded handshake to {remote_path}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.error(f"[WireGuard] Handshake upload failed: {e}")
                if hasattr(e, 'stderr'):
                    logging.error(f"[WireGuard] Stderr: {e.stderr.decode('utf-8').strip()}")

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
                subprocess.run(["wg-quick", "down", self.wg_config_path], check=True)
                os.remove(self.wg_config_path)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logging.error(f"[WireGuard] Failed to disconnect: {e}")
        
        ui.remove('wg_status')