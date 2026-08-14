import os
import subprocess
import paramiko

class BaseConnector:
    def execute(self, command: str) -> tuple[str, str, int]:
        raise NotImplementedError

class LocalConnector(BaseConnector):
    def __init__(self):
        pass
        
    def execute(self, command: str) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), 1

class SSHConnector(BaseConnector):
    def __init__(self, host, port, username, password=None, key_path=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # In a real environment, we should use RejectPolicy or check host keys securely. 
        # For simplicity in this project, we auto-add.
        
        self.connect()

    def connect(self):
        try:
            if self.key_path:
                key = paramiko.RSAKey.from_private_key_file(self.key_path)
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key,
                    timeout=10
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=10
                )
        except Exception as e:
            raise RuntimeError(f"Failed to connect via SSH to {self.host}: {str(e)}")

    def execute(self, command: str) -> tuple[str, str, int]:
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=15)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8').strip()
            err = stderr.read().decode('utf-8').strip()
            return out, err, exit_code
        except Exception as e:
            return "", str(e), -1

    def close(self):
        if self.client:
            self.client.close()

def get_connector(target_type: str, env_vars: dict) -> BaseConnector:
    if target_type == "local":
        return LocalConnector()
    elif target_type == "ssh":
        host = env_vars.get("SSH_HOST")
        port = int(env_vars.get("SSH_PORT", 22))
        username = env_vars.get("SSH_USER")
        password = env_vars.get("SSH_PASSWORD")
        key_path = env_vars.get("SSH_KEY_PATH")
        
        if not host or not username:
            raise ValueError("SSH_HOST and SSH_USER must be provided for SSH targets.")
            
        return SSHConnector(host, port, username, password, key_path)
    else:
        raise ValueError(f"Unknown target type: {target_type}")
