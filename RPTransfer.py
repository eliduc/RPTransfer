#
# RPTransfer - Universal File Transfer Application
# Version: 1.5
#
# Recent Improvements:
# - (v1.6) Added functionality to use .ico and .json file from the same directory the app was launched
# - (v1.5) Added preservation of file sorting when navigating between directories
# - (v1.5) Added saving/restoring of last PC directory on exit/startup
# - (v1.4.1) Corrected the multiple file upload/download freeze error
# - (v1.4) Added show/hide password toggle to the Connection Dialog.
# - (v1.3) Added "Deauthorize" button to the Device List window for clearing saved credentials.
# - (v1.3) Refined the Device List window's height to dynamically adjust based on the
#   number of configured devices.
# - (v1.3) Corrected the scrollbar implementation within the Device List window.
#


import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import paramiko
import os
import sys
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import stat
import time
import shutil
import socket
import json
import keyring
from pathlib import Path
import functools
import hashlib



# Constants
MAX_WORKERS = 5
BUFFER_SIZE = 32768  # 32KB chunks for file transfer
CACHE_TIMEOUT = 60  # seconds
PAGE_SIZE = 500  # items per page for large directories

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("file_transfer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("RPTransfer")

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
    
CONFIG_FILE = resource_path("rptrans_config.json")

class Config:
    """Configuration manager class"""
    @staticmethod
    def load_devices():
        """Load device configuration from file or return defaults"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Ensure we have the necessary structure
                    if 'devices' not in config:
                        config['devices'] = {}
                    return config
            else:
                # Default configuration
                default_config = {
                    'devices': {
                        'FR': {'type': 'pi', 'connection': 'pi@fr', 'directory': '/home/pi/GP/'},
                        'GP': {'type': 'pi', 'connection': 'pi@gp', 'directory': '/home/pi/CheckGate.'},
                        'KODI': {'type': 'pi', 'connection': 'root@libreELEC', 'directory': '/storage/videos/'},
                        'Zerow': {'type': 'pi', 'connection': 'pi@192.168.2.68', 'directory': '/home/pi/'},
                        'ZerowW128': {'type': 'pi', 'connection': 'pi@ZeroW128', 'directory': '/home/pi/'},
                        'Remote PC': {'type': 'pc', 'connection': 'user@192.168.2.39', 'directory': 'c:/work/Pictures'}
                    }
                }
                Config.save_devices(default_config)
                return default_config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            return {'devices': {}}
    
    @staticmethod
    def save_devices(config):
        """Save device configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    @staticmethod
    def add_device(name, device_type, connection, directory):
        """Add or update a device in the configuration"""
        config = Config.load_devices()
        config['devices'][name] = {
            'type': device_type,
            'connection': connection,
            'directory': directory
        }
        return Config.save_devices(config)
    
    @staticmethod
    def remove_device(name):
        """Remove a device from the configuration"""
        config = Config.load_devices()
        if name in config['devices']:
            del config['devices'][name]
            return Config.save_devices(config)
        return False
    
    @staticmethod
    def get_last_local_directory():
        """Get the last used local directory"""
        try:
            config = Config.load_devices()
            return config.get('last_local_directory', str(Path.home()))
        except Exception:
            return str(Path.home())
    
    @staticmethod
    def save_last_local_directory(directory):
        """Save the last used local directory"""
        try:
            config = Config.load_devices()
            config['last_local_directory'] = directory
            return Config.save_devices(config)
        except Exception as e:
            logger.error(f"Error saving last local directory: {str(e)}")
            return False

class CredentialManager:
    """Secure credential manager using keyring"""
    @staticmethod
    def save_credentials(device_name, username, password):
        """Save credentials securely"""
        try:
            keyring.set_password("rptrans", f"{device_name}_{username}", password)
            return True
        except Exception as e:
            logger.error(f"Error saving credentials: {str(e)}")
            return False
    
    @staticmethod
    def get_credentials(device_name, username):
        """Retrieve credentials securely"""
        try:
            return keyring.get_password("rptrans", f"{device_name}_{username}")
        except Exception as e:
            logger.error(f"Error retrieving credentials: {str(e)}")
            return None
    
    @staticmethod
    def delete_credentials(device_name, username):
        """Delete stored credentials"""
        try:
            keyring.delete_password("rptrans", f"{device_name}_{username}")
            return True
        except Exception as e:
            logger.error(f"Error deleting credentials: {str(e)}")
            return False

class FileItem:
    """Represents a file or directory item with metadata"""
    def __init__(self, name, path, is_dir=False, size=0, modified=None, extension=""):
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.modified = modified or datetime.now()
        self.extension = extension
    
    @property
    def formatted_size(self):
        """Return formatted file size"""
        return format_size(self.size)
    
    @property
    def formatted_date(self):
        """Return formatted modification date"""
        return self.modified.strftime('%Y-%m-%d %H:%M:%S')
    
    @classmethod
    def from_local_path(cls, path):
        """Create a FileItem from a local path"""
        path_obj = Path(path)
        stat_info = path_obj.stat()
        is_dir = path_obj.is_dir()
        
        return cls(
            name=path_obj.name,
            path=str(path_obj),
            is_dir=is_dir,
            size=0 if is_dir else stat_info.st_size,
            modified=datetime.fromtimestamp(stat_info.st_mtime),
            extension="" if is_dir else path_obj.suffix
        )
    
    @classmethod
    def from_sftp_attr(cls, attr, parent_path):
        """Create a FileItem from SFTP attributes"""
        is_dir = stat.S_ISDIR(attr.st_mode)
        path = os.path.join(parent_path, attr.filename).replace('\\', '/')
        name, ext = os.path.splitext(attr.filename)
        
        return cls(
            name=attr.filename,
            path=path,
            is_dir=is_dir,
            size=0 if is_dir else attr.st_size,
            modified=datetime.fromtimestamp(attr.st_mtime),
            extension="" if is_dir else ext
        )

class FileTransferTask:
    """Represents a file transfer task"""
    def __init__(self, source_path, dest_path, size, is_upload=True):
        self.source_path = source_path
        self.dest_path = dest_path
        self.size = size
        self.is_upload = is_upload
        self.bytes_transferred = 0
        self.status = "pending"  # pending, in_progress, completed, failed, cancelled
        self.error = None
    
    @property
    def filename(self):
        """Return the filename part of the source path"""
        return os.path.basename(self.source_path)
    
    @property
    def progress(self):
        """Return the progress percentage"""
        if self.size == 0:
            return 100
        return min(100, int((self.bytes_transferred * 100) / self.size))

class TransferManager:
    """Manages file transfers using a worker pool"""
    def __init__(self, sftp, max_workers=MAX_WORKERS):
        self.sftp = sftp
        self.queue = queue.Queue()
        self.active_tasks = {}
        self.completed_tasks = []
        self.failed_tasks = []
        self.cancelled = False
        self.overwrite_all = False
        self.skip_all = False
        # Reduce workers to 1 to avoid SFTP concurrency issues
        self.executor = ThreadPoolExecutor(max_workers=1)  # CHANGED from max_workers
        self.worker_thread = None
        self.callbacks = {
            'progress': [],
            'file_complete': [],
            'all_complete': [],
            'error': []
        }
        # Lock for SFTP operations
        self._sftp_lock = threading.Lock()
    
    def add_callback(self, event_type, callback):
        """Add a callback for transfer events"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def _notify_callbacks(self, event_type, *args, **kwargs):
        """
        Notify all registered callbacks for an event.
        """
        for callback in self.callbacks.get(event_type, []):
            try:
                # Always schedule callbacks on main thread
                root = tk._default_root
                if root and root.winfo_exists():
                    root.after(0, lambda cb=callback, a=args, kw=kwargs: cb(*a, **kw))
                else:
                    callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in callback: {str(e)}")
    
    def add_task(self, task):
        """Add a transfer task to the queue"""
        self.queue.put(task)
        self.active_tasks[task.source_path] = task
    
    def start_workers(self):
        """Start the worker thread to process file transfers"""
        if self.worker_thread and self.worker_thread.is_alive():
            return
        
        self.cancelled = False
        self.worker_thread = threading.Thread(target=self._process_queue)
        self.worker_thread.daemon = True
        self.worker_thread.start()
    
    def cancel_all(self):
        """Cancel all pending transfers"""
        self.cancelled = True
        # Clear the queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except queue.Empty:
                break
        
        # Update status of active tasks
        for task in self.active_tasks.values():
            if task.status == "pending":
                task.status = "cancelled"
    
    def _process_queue(self):
        """Process the transfer queue"""
        futures = []
        
        while not self.cancelled:
            try:
                task = self.queue.get(timeout=0.5)
                
                # Submit the task to the thread pool
                if task.is_upload:
                    future = self.executor.submit(
                        self._upload_file, task.source_path, task.dest_path, task
                    )
                else:
                    future = self.executor.submit(
                        self._download_file, task.source_path, task.dest_path, task
                    )
                
                futures.append(future)
                
                # Clean up completed futures
                for future in list(futures):
                    if future.done():
                        futures.remove(future)
                
                self.queue.task_done()
            
            except queue.Empty:
                # Check if all tasks are done
                if self.queue.empty() and all(future.done() for future in futures):
                    # Wait a moment to ensure all callbacks have been processed
                    time.sleep(0.1)
                    self._notify_callbacks('all_complete')
                    break
        
        # Wait for all tasks to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error waiting for future: {str(e)}")
    
    def _upload_file(self, local_path, remote_path, task):
        """Upload a file with progress tracking"""
        try:
            task.status = "in_progress"
            
            # Create remote directories if needed (with lock)
            remote_dir = os.path.dirname(remote_path)
            with self._sftp_lock:
                try:
                    self.sftp.chdir(remote_dir)
                except IOError:
                    self._make_remote_dirs(remote_dir)
            
            # Use custom implementation with chunked uploads
            with open(local_path, 'rb') as local_file:
                with self._sftp_lock:
                    remote_file = self.sftp.open(remote_path, 'wb')
                
                try:
                    chunk = local_file.read(BUFFER_SIZE)
                    while chunk and not self.cancelled:
                        with self._sftp_lock:
                            remote_file.write(chunk)
                        task.bytes_transferred += len(chunk)
                        self._notify_callbacks('progress', task)
                        chunk = local_file.read(BUFFER_SIZE)
                finally:
                    with self._sftp_lock:
                        remote_file.close()
            
            if self.cancelled:
                task.status = "cancelled"
                with self._sftp_lock:
                    try:
                        self.sftp.remove(remote_path)
                    except:
                        pass
            else:
                task.status = "completed"
                self.completed_tasks.append(task)
                self._notify_callbacks('file_complete', task)
            
            return True
        
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            self.failed_tasks.append(task)
            self._notify_callbacks('error', task, str(e))
            logger.error(f"Upload failed: {str(e)}")
            return False
    
    def _download_file(self, remote_path, local_path, task):
        """Download a file with progress tracking"""
        try:
            task.status = "in_progress"
            
            # Create local directories if needed
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Use custom implementation with chunked downloads
            with self._sftp_lock:
                remote_file = self.sftp.open(remote_path, 'rb')
            
            try:
                with open(local_path, 'wb') as local_file:
                    chunk = remote_file.read(BUFFER_SIZE)
                    while chunk and not self.cancelled:
                        local_file.write(chunk)
                        task.bytes_transferred += len(chunk)
                        self._notify_callbacks('progress', task)
                        with self._sftp_lock:
                            chunk = remote_file.read(BUFFER_SIZE)
            finally:
                with self._sftp_lock:
                    remote_file.close()
            
            if self.cancelled:
                task.status = "cancelled"
                try:
                    os.remove(local_path)
                except:
                    pass
            else:
                task.status = "completed"
                self.completed_tasks.append(task)
                self._notify_callbacks('file_complete', task)
            
            return True
        
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            self.failed_tasks.append(task)
            self._notify_callbacks('error', task, str(e))
            logger.error(f"Download failed: {str(e)}")
            return False
    
    def _make_remote_dirs(self, path):
        """Create remote directories recursively (must be called with lock held)"""
        path = path.rstrip('/')
        if not path:
            return
        
        try:
            self.sftp.chdir(path)
        except IOError:
            self._make_remote_dirs(os.path.dirname(path))
            try:
                self.sftp.mkdir(path)
            except IOError as e:
                logger.error(f"Failed to create remote directory {path}: {str(e)}")
                raise

class FileSystemModel:
    """Model for file system operations"""
    def __init__(self):
        self.local_cache = {}
        self.remote_cache = {}
        self.ssh = None
        self.sftp = None
        self.transfer_manager = None
        self.remote_directory = None
        # Load last used local directory
        last_dir = Config.get_last_local_directory()
        if os.path.exists(last_dir) and os.path.isdir(last_dir):
            self.local_directory = last_dir
        else:
            self.local_directory = str(Path.home())
        self.device_type = None
        self.device_name = None
        self._remote_disk_info = None
        self._remote_disk_info_time = 0
    
    @property
    def is_connected(self):
        """Check if connected to remote system"""
        return self.ssh is not None and self.sftp is not None
    
    def connect(self, hostname, username, password, directory, device_type='pc', device_name=None):
        """Connect to remote system"""
        try:
            logger.info(f"Connecting to {hostname}")
            
            # Clean up any existing connection
            self.disconnect()
            
            # Set remote directory
            self.remote_directory = normalize_path(directory, is_remote=True)
            if not self.remote_directory.endswith('/'):
                self.remote_directory += '/'
            
            # Set device info
            self.device_type = device_type
            self.device_name = device_name
            
            # Create SSH client with better security
            self.ssh = paramiko.SSHClient()
            
            # Use system host keys if available, otherwise use warning policy
            self.ssh.load_system_host_keys()
            self.ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
            
            # Connect with timeout
            self.ssh.connect(
                hostname=hostname,
                username=username,
                password=password,
                look_for_keys=True,  # Try to use key-based auth
                allow_agent=True,    # Try to use ssh-agent
                timeout=30
            )
            
            logger.info("SSH connection successful")
            
            # Open SFTP session
            self.sftp = self.ssh.open_sftp()
            logger.info("SFTP session opened")
            
            # Test connection by listing directory
            try:
                self.sftp.listdir(self.remote_directory)
                logger.info("Directory listing successful")
            except FileNotFoundError:
                self.disconnect()
                raise FileNotFoundError(f"Remote directory not found: {self.remote_directory}")
            except PermissionError:
                self.disconnect()
                raise PermissionError(f"Access denied to remote directory: {self.remote_directory}")
            
            # Create transfer manager
            self.transfer_manager = TransferManager(self.sftp)
            
            # Save successful connection credentials if asked
            if device_name:
                CredentialManager.save_credentials(device_name, username, password)
            
            return True
        
        except paramiko.AuthenticationException:
            logger.error("Authentication failed")
            self.disconnect()
            raise AuthenticationError("Authentication failed. Please verify username and password.")
        
        except paramiko.SSHException as e:
            logger.error(f"SSH Protocol error: {str(e)}")
            self.disconnect()
            raise ConnectionError(f"SSH error: {str(e)}")
        
        except socket.error as e:
            logger.error(f"Socket error: {str(e)}")
            self.disconnect()
            raise ConnectionError(f"Network error: {str(e)}")
        
        except Exception as e:
            logger.error(f"Connection error: {str(e)}", exc_info=True)
            self.disconnect()
            raise ConnectionError(f"Failed to connect: {str(e)}")
    
    def disconnect(self):
        """Disconnect from remote system"""
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        
        self.transfer_manager = None
        self.device_type = None
        self.device_name = None
        self.remote_directory = None
        self.remote_cache = {}
        self._remote_disk_info = None
        return True
    
    def get_local_files(self, directory=None, use_cache=True):
        """Get files from local directory with caching"""
        directory = directory or self.local_directory
        directory = normalize_path(directory)
        
        # Check cache first
        cache_key = directory
        if use_cache and cache_key in self.local_cache:
            cache_entry = self.local_cache[cache_key]
            if time.time() - cache_entry['timestamp'] < CACHE_TIMEOUT:
                logger.debug(f"Using cached local directory: {directory}")
                return cache_entry['files']
        
        logger.debug(f"Reading local directory: {directory}")
        files = []
        
        try:
            # Add parent directory entry if not root
            path_obj = Path(directory)
            if path_obj != path_obj.anchor:
                parent = FileItem('..', str(path_obj.parent), is_dir=True)
                files.append(parent)
            
            # List directory contents
            for entry in path_obj.iterdir():
                try:
                    files.append(FileItem.from_local_path(entry))
                except (PermissionError, OSError):
                    continue
            
            # Update cache
            self.local_cache[cache_key] = {
                'files': files,
                'timestamp': time.time()
            }
            
            return files
        
        except FileNotFoundError:
            logger.error(f"Directory not found: {directory}")
            raise
        
        except PermissionError:
            logger.error(f"Permission denied: {directory}")
            raise
    
    def get_remote_files(self, directory=None, use_cache=True):
        """Get files from remote directory with caching"""
        if not self.is_connected:
            raise ConnectionError("Not connected to remote system")
        
        directory = directory or self.remote_directory
        directory = normalize_path(directory, is_remote=True)
        
        # Check cache first
        cache_key = directory
        if use_cache and cache_key in self.remote_cache:
            cache_entry = self.remote_cache[cache_key]
            if time.time() - cache_entry['timestamp'] < CACHE_TIMEOUT:
                logger.debug(f"Using cached remote directory: {directory}")
                return cache_entry['files']
        
        logger.debug(f"Reading remote directory: {directory}")
        files = []
        
        try:
            # Add parent directory entry if not root
            if directory != '/':
                parent = FileItem('..', os.path.dirname(directory.rstrip('/')), is_dir=True)
                files.append(parent)
            
            # List directory contents
            items = self.sftp.listdir_attr(directory)
            for item_attr in items:
                files.append(FileItem.from_sftp_attr(item_attr, directory))
            
            # Update cache
            self.remote_cache[cache_key] = {
                'files': files,
                'timestamp': time.time()
            }
            
            return files
        
        except FileNotFoundError:
            logger.error(f"Remote directory not found: {directory}")
            raise
        
        except PermissionError:
            logger.error(f"Access denied to remote directory: {directory}")
            raise
    
    def get_local_disk_info(self, path=None):
        """Get local disk information"""
        path = path or self.local_directory
        
        try:
            if os.path.exists(path):
                total, used, free = shutil.disk_usage(path)
                return {
                    'total': total,
                    'used': used,
                    'free': free,
                    'volume': path
                }
        except Exception as e:
            logger.error(f"Error getting local disk info: {str(e)}")
        
        return None
    
    def get_remote_disk_info(self, path=None):
        """Get remote disk information with caching"""
        if not self.is_connected:
            return None
        
        path = path or self.remote_directory
        
        try:
            # Check cache
            current_time = time.time()
            if self._remote_disk_info and (current_time - self._remote_disk_info_time) < CACHE_TIMEOUT:
                return self._remote_disk_info
            
            # Run df command
            cmd = f"df -P '{path}'"
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            output = stdout.readlines()
            error_output = stderr.read().decode().strip()
            
            if error_output:
                logger.error(f"Error output from df command: {error_output}")
                return None
            
            # Parse output
            data_line = None
            for line in output[1:]:
                line = line.strip()
                if line:
                    data_line = line
                    break
            
            if not data_line:
                return None
            
            data = data_line.split()
            if len(data) >= 6:
                volume = data[0]
                total = int(data[1]) * 1024
                used = int(data[2]) * 1024
                free = int(data[3]) * 1024
                
                # Cache the result
                self._remote_disk_info = {
                    'volume': volume,
                    'total': total,
                    'used': used,
                    'free': free
                }
                self._remote_disk_info_time = current_time
                
                return self._remote_disk_info
            
            return None
        
        except Exception as e:
            logger.error(f"Error getting remote disk info: {str(e)}", exc_info=True)
            return None
    
    def create_local_directory(self, parent_dir, name):
        """Create a new local directory"""
        try:
            path = os.path.join(parent_dir, name)
            os.makedirs(path, exist_ok=True)
            
            # Invalidate cache
            if parent_dir in self.local_cache:
                del self.local_cache[parent_dir]
            
            return path
        except Exception as e:
            logger.error(f"Failed to create local directory: {str(e)}")
            raise
    
    def create_remote_directory(self, parent_dir, name):
        """Create a new remote directory"""
        if not self.is_connected:
            raise ConnectionError("Not connected to remote system")
        
        try:
            path = os.path.join(parent_dir, name).replace('\\', '/')
            self.sftp.mkdir(path)
            
            # Invalidate cache
            if parent_dir in self.remote_cache:
                del self.remote_cache[parent_dir]
            
            return path
        except Exception as e:
            logger.error(f"Failed to create remote directory: {str(e)}")
            raise
    
    def delete_local_item(self, path, recursive=False):
        """Delete a local file or directory"""
        try:
            path_obj = Path(path)
            
            if path_obj.is_file():
                path_obj.unlink()
            elif path_obj.is_dir():
                if recursive:
                    shutil.rmtree(path)
                else:
                    path_obj.rmdir()
            
            # Invalidate cache
            parent_dir = str(path_obj.parent)
            if parent_dir in self.local_cache:
                del self.local_cache[parent_dir]
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete local item: {str(e)}")
            raise
    
    def delete_remote_item(self, path, recursive=False):
        """Delete a remote file or directory"""
        if not self.is_connected:
            raise ConnectionError("Not connected to remote system")
        
        try:
            # Check if file or directory
            try:
                attrs = self.sftp.stat(path)
                is_dir = stat.S_ISDIR(attrs.st_mode)
            except:
                return False
            
            if is_dir:
                if recursive:
                    self._remove_remote_dir_recursive(path)
                else:
                    self.sftp.rmdir(path)
            else:
                self.sftp.remove(path)
            
            # Invalidate cache
            parent_dir = os.path.dirname(path)
            if parent_dir in self.remote_cache:
                del self.remote_cache[parent_dir]
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete remote item: {str(e)}")
            raise
    
    def _remove_remote_dir_recursive(self, path):
        """Recursively remove a remote directory"""
        for item in self.sftp.listdir_attr(path):
            item_path = os.path.join(path, item.filename).replace('\\', '/')
            if stat.S_ISDIR(item.st_mode):
                self._remove_remote_dir_recursive(item_path)
            else:
                self.sftp.remove(item_path)
        self.sftp.rmdir(path)
    
    def calculate_checksum(self, path, is_remote=False, algorithm='sha256'):
        """Calculate file checksum"""
        hasher = hashlib.new(algorithm)
        
        try:
            if is_remote and self.is_connected:
                with self.sftp.open(path, 'rb') as remote_file:
                    for chunk in iter(lambda: remote_file.read(BUFFER_SIZE), b''):
                        hasher.update(chunk)
            else:
                with open(path, 'rb') as local_file:
                    for chunk in iter(lambda: local_file.read(BUFFER_SIZE), b''):
                        hasher.update(chunk)
            
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum: {str(e)}")
            raise

class AuthenticationError(Exception):
    """Exception raised for authentication failures"""
    pass

class ConnectionError(Exception):
    """Exception raised for connection failures"""
    pass

# UI Components
class DeviceListDialog(tk.Toplevel):
    def __init__(self, parent, x, y):
        super().__init__(parent)
        self.title("Select Device Type")
        self.result = None
        self.transient(parent)
        
        self.device_configs = Config.load_devices().get('devices', {})
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(list_frame, text="Saved Devices:").pack(anchor='w')

        num_devices = len(self.device_configs)
        desired_height = num_devices + 1
        listbox_height = max(5, min(desired_height, 15))
        listbox_width = 25

        self.listbox = tk.Listbox(
            list_frame,
            width=listbox_width,
            height=listbox_height,
            font=('TkDefaultFont', 10),
            selectmode=tk.SINGLE,
            activestyle='none',
            relief=tk.FLAT,
            bg='white'
        )

        scrollbar = ttk.Scrollbar(
            list_frame,
            orient="vertical",
            command=self.listbox.yview
        )
        self.listbox.config(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=(0,5))
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(0,5))

        for device_name in self.device_configs:
            self.listbox.insert(tk.END, device_name)
        
        device_buttons_frame = ttk.Frame(main_frame)
        device_buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(device_buttons_frame, text="Add", command=self.add_device, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Button(device_buttons_frame, text="Edit", command=self.edit_device, width=8).pack(side=tk.LEFT, padx=5)
        
        # --- New Deauthorize Button ---
        self.deauthorize_button = ttk.Button(device_buttons_frame, text="Deauthorize", command=self.deauthorize_device, width=11, state=tk.DISABLED)
        self.deauthorize_button.pack(side=tk.LEFT, padx=5)
        # --- End New Deauthorize Button ---
        
        ttk.Button(device_buttons_frame, text="Remove", command=self.remove_device, width=8).pack(side=tk.LEFT, padx=5)
        
        action_buttons_frame = ttk.Frame(main_frame)
        action_buttons_frame.pack(fill=tk.X, pady=10) 
        
        ttk.Button(action_buttons_frame, text="Connect", command=self.ok, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_buttons_frame, text="Cancel", command=self.cancel, width=10).pack(side=tk.RIGHT, padx=5)
        
        self.listbox.bind('<Double-Button-1>', lambda e: self.ok())
        self.listbox.bind('<Return>', lambda e: self.ok())
        self.listbox.bind('<Escape>', lambda e: self.cancel())
        # --- Bind selection change to update button state ---
        self.listbox.bind('<<ListboxSelect>>', self.on_selection_change)
        
        self.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.geometry(f"+{x}+{y}")
        
        if self.listbox.size() > 0:
            self.listbox.select_set(0)
        
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.listbox.focus_set()
        
        # --- Initial update of deauthorize button state ---
        self.update_deauthorize_button_state() 
        
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        
        # print(f"DEBUG: DeviceListDialog final calculated dimensions: width={width}, height={height}") # Optional: remove if not needed
        
        x_pos = parent.winfo_rootx() + (parent.winfo_width() // 2) - (width // 2)
        y_pos = parent.winfo_rooty() + (parent.winfo_height() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x_pos}+{y_pos}")

    def on_selection_change(self, event=None):
        """Called when the listbox selection changes."""
        self.update_deauthorize_button_state()

    def update_deauthorize_button_state(self):
        """Enable or disable the Deauthorize button based on credential existence."""
        if not self.listbox.curselection():
            self.deauthorize_button.config(state=tk.DISABLED)
            return

        selected_index = self.listbox.curselection()[0]
        device_name_key = self.listbox.get(selected_index)
        device_info = self.device_configs.get(device_name_key)

        if not device_info or 'connection' not in device_info:
            self.deauthorize_button.config(state=tk.DISABLED)
            return

        connection_str = device_info['connection']
        if '@' not in connection_str:
            self.deauthorize_button.config(state=tk.DISABLED)
            return

        try:
            username, hostname = connection_str.split('@', 1)
            if CredentialManager.get_credentials(hostname, username): # [cite: RPTransfer_1.2.py]
                self.deauthorize_button.config(state=tk.NORMAL)
            else:
                self.deauthorize_button.config(state=tk.DISABLED)
        except ValueError:
            self.deauthorize_button.config(state=tk.DISABLED)
            logger.warning(f"Malformed connection string for {device_name_key}: {connection_str}")
        except Exception as e:
            logger.error(f"Error checking credentials for {device_name_key}: {e}")
            self.deauthorize_button.config(state=tk.DISABLED)

    def deauthorize_device(self):
        """Remove stored credentials for the selected device."""
        if not self.listbox.curselection():
            messagebox.showwarning("Deauthorize", "Please select a device to deauthorize.")
            return

        selected_index = self.listbox.curselection()[0]
        device_name_key = self.listbox.get(selected_index)
        device_info = self.device_configs.get(device_name_key)

        if not device_info or 'connection' not in device_info:
            messagebox.showerror("Error", "Could not retrieve device information.")
            return

        connection_str = device_info['connection']
        if '@' not in connection_str:
            messagebox.showerror("Error", f"Malformed connection string for {device_name_key}: {connection_str}")
            return

        try:
            username, hostname = connection_str.split('@', 1)
        except ValueError:
            messagebox.showerror("Error", f"Could not parse username/hostname for {device_name_key}.")
            return

        if not CredentialManager.get_credentials(hostname, username):
            messagebox.showinfo("Deauthorize", f"No saved credentials found for {device_name_key} ({username}@{hostname}).")
            self.update_deauthorize_button_state() # Ensure button state is correct
            return

        if messagebox.askyesno("Confirm Deauthorization", 
                               f"Are you sure you want to remove saved credentials for {device_name_key} ({username}@{hostname})?"):
            if CredentialManager.delete_credentials(hostname, username): # [cite: RPTransfer_1.2.py]
                messagebox.showinfo("Success", f"Credentials for {device_name_key} have been removed.")
            else:
                messagebox.showerror("Error", f"Failed to remove credentials for {device_name_key}.")
            
            self.update_deauthorize_button_state() # Update button state after attempting deletion

    # Ensure add_device, edit_device, and remove_device also call update_deauthorize_button_state
    # if they change the selection or the listbox content in a way that <<ListboxSelect>> might not cover all cases.
    # However, <<ListboxSelect>> should generally handle selection changes.
    # If list becomes empty after remove_device, on_selection_change won't fire if nothing is selected.
    
    def add_device(self):
        """Add a new device configuration"""
        dialog = DeviceEditDialog(self, title="Add Device") # [cite: RPTransfer_1.2.py]
        self.wait_window(dialog)
        
        if dialog.result:
            name, device_type, connection, directory = dialog.result
            Config.add_device(name, device_type, connection, directory) # [cite: RPTransfer_1.2.py]
            self.device_configs = Config.load_devices().get('devices', {})
            
            self.listbox.delete(0, tk.END)
            for device_name_key in self.device_configs:
                self.listbox.insert(tk.END, device_name_key)
            
            for i, device_name_key_loop in enumerate(self.device_configs.keys()):
                if device_name_key_loop == name:
                    self.listbox.select_set(i)
                    self.listbox.see(i)
                    break
            self.update_deauthorize_button_state() # Explicit call after list modification

    def edit_device(self):
        """Edit selected device configuration"""
        if not self.listbox.curselection():
            messagebox.showwarning("Warning", "Please select a device to edit.") # [cite: RPTransfer_1.2.py]
            return
        
        selected_index = self.listbox.curselection()[0]
        selected_name = self.listbox.get(selected_index)
        device_info = self.device_configs[selected_name]
        
        dialog = DeviceEditDialog(
            self,
            title="Edit Device",
            name=selected_name,
            device_type=device_info.get('type', 'pi'),
            connection=device_info.get('connection', ''),
            directory=device_info.get('directory', '')
        ) # [cite: RPTransfer_1.2.py]
        self.wait_window(dialog)
        
        if dialog.result:
            name, device_type, connection, directory = dialog.result
            if name != selected_name:
                Config.remove_device(selected_name) # [cite: RPTransfer_1.2.py]
            Config.add_device(name, device_type, connection, directory) # [cite: RPTransfer_1.2.py]
            self.device_configs = Config.load_devices().get('devices', {})
            
            self.listbox.delete(0, tk.END)
            for device_name_key in self.device_configs:
                self.listbox.insert(tk.END, device_name_key)
            
            for i, device_name_key_loop in enumerate(self.device_configs.keys()):
                if device_name_key_loop == name:
                    self.listbox.select_set(i)
                    self.listbox.see(i)
                    break
            self.update_deauthorize_button_state() # Explicit call after list modification

    def remove_device(self):
        """Remove selected device configuration"""
        if not self.listbox.curselection():
            messagebox.showwarning("Warning", "Please select a device to remove.") # [cite: RPTransfer_1.2.py]
            return
        
        selected_name = self.listbox.get(self.listbox.curselection()[0])
        device_info = self.device_configs.get(selected_name) # Get info before potential deletion
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to remove '{selected_name}'?"): # [cite: RPTransfer_1.2.py]
            Config.remove_device(selected_name) # [cite: RPTransfer_1.2.py]
            
            # Attempt to remove credentials if device_info was found and connection string is valid
            if device_info and 'connection' in device_info and '@' in device_info['connection']:
                try:
                    username, hostname = device_info['connection'].split('@', 1)
                    CredentialManager.delete_credentials(hostname, username) # [cite: RPTransfer_1.2.py]
                    logger.info(f"Also deleted credentials for removed device {selected_name} ({username}@{hostname})")
                except ValueError:
                    logger.warning(f"Could not parse username/hostname to delete credentials for removed device {selected_name}")
                except Exception as e:
                    logger.error(f"Error deleting credentials for removed device {selected_name}: {e}")

            self.device_configs = Config.load_devices().get('devices', {})
            
            self.listbox.delete(0, tk.END)
            for device_name_key in self.device_configs:
                self.listbox.insert(tk.END, device_name_key)
            
            if self.listbox.size() > 0:
                self.listbox.select_set(0)
                self.listbox.see(0)
            
            self.update_deauthorize_button_state() # Explicit call after list modification/selection change

    # ok and cancel methods remain unchanged from your RPTransfer_1.2.py
    def ok(self, event=None):
        """Handle OK button"""
        if not self.listbox.curselection():
            messagebox.showwarning("Warning", "Please select a device.") # [cite: RPTransfer_1.2.py]
            return
        
        selected_name = self.listbox.get(self.listbox.curselection()[0])
        device_info = self.device_configs[selected_name]
        
        device_info['name'] = selected_name
        self.result = device_info
        
        self.destroy()

    def cancel(self, event=None):
        """Handle Cancel button"""
        self.result = None
        self.destroy()

class DeviceEditDialog(tk.Toplevel):
    """Dialog for adding or editing device configurations"""
    def __init__(self, parent, title="Device", name="", device_type="pi", connection="", directory=""):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.transient(parent)
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Device name
        ttk.Label(main_frame, text="Device Name:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.name_entry = ttk.Entry(main_frame, width=30)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        self.name_entry.insert(0, name)
        
        # Device type
        ttk.Label(main_frame, text="Device Type:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.type_var = tk.StringVar(value=device_type)
        type_frame = ttk.Frame(main_frame)
        type_frame.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        ttk.Radiobutton(type_frame, text="Raspberry Pi", variable=self.type_var, value="pi").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="PC/Server", variable=self.type_var, value="pc").pack(side=tk.LEFT, padx=5)
        
        # Connection string
        ttk.Label(main_frame, text="Connection:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.connection_entry = ttk.Entry(main_frame, width=30)
        self.connection_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
        self.connection_entry.insert(0, connection or "user@hostname")
        
        # Help text for connection
        connection_help = ttk.Label(main_frame, text="Format: username@hostname", foreground="gray")
        connection_help.grid(row=3, column=1, padx=5, sticky='w')
        
        # Remote directory
        ttk.Label(main_frame, text="Remote Directory:").grid(row=4, column=0, padx=5, pady=5, sticky='e')
        self.directory_entry = ttk.Entry(main_frame, width=30)
        self.directory_entry.grid(row=4, column=1, padx=5, pady=5, sticky='ew')
        self.directory_entry.insert(0, directory or "/home/user/")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=self.save, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel, width=10).pack(side=tk.LEFT, padx=5)
        
        # Configure grid
        main_frame.columnconfigure(1, weight=1)
        
        # Bindings
        self.bind('<Return>', lambda e: self.save())
        self.bind('<Escape>', lambda e: self.cancel())
        
        # Set focus
        self.name_entry.focus_set()
        
        # Make dialog modal
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        # Center the dialog relative to parent
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (width // 2)
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def save(self, event=None):
        """Save the device configuration"""
        name = self.name_entry.get().strip()
        device_type = self.type_var.get()
        connection = self.connection_entry.get().strip()
        directory = self.directory_entry.get().strip()
        
        # Validation
        if not name:
            messagebox.showerror("Error", "Device name is required.")
            self.name_entry.focus_set()
            return
        
        if not connection or '@' not in connection:
            messagebox.showerror("Error", "Connection must be in format 'username@hostname'")
            self.connection_entry.focus_set()
            return
        
        if not directory:
            messagebox.showerror("Error", "Remote directory is required.")
            self.directory_entry.focus_set()
            return
        
        # Ensure directory ends with slash
        if not directory.endswith('/'):
            directory += '/'
        
        self.result = (name, device_type, connection, directory)
        self.destroy()
    
    def cancel(self, event=None):
        """Cancel the operation"""
        self.result = None
        self.destroy()

class ConnectionDialog(tk.Toplevel):
    """Dialog for entering connection details"""
    def __init__(self, parent, x, y, device_type='pi', default_connection=None, default_directory=None):
        super().__init__(parent)
        self.title("Remote Connection")
        self.result = None
        self.transient(parent)
        self.device_type = device_type
        
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection string
        ttk.Label(main_frame, text="Username@Hostname:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.connection_entry = ttk.Entry(main_frame, width=30)
        self.connection_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky='ew') # Span to align with password + eye
        if device_type == 'pi':
            self.connection_entry.insert(0, default_connection or "pi@raspberrypi.local")
        else:
            self.connection_entry.insert(0, default_connection or "user@hostname")
        
        # Password
        ttk.Label(main_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.password_entry = ttk.Entry(main_frame, show="*", width=25) # Adjusted width
        self.password_entry.grid(row=1, column=1, padx=(5,0), pady=5, sticky='ew')
        
        # --- Show/Hide Password Toggle ---
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_button = ttk.Checkbutton(
            main_frame, 
            text="👁", # You can use text "Show" or a unicode eye
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            style="Toolbutton" # Makes it look more like a button if theme supports
        )
        self.show_password_button.grid(row=1, column=2, padx=(0,5), pady=5, sticky='w')
        # --- End Show/Hide Password Toggle ---
        
        # Save password checkbox
        self.save_password_var = tk.BooleanVar(value=False) #
        ttk.Checkbutton(
            main_frame,
            text="Save password securely",
            variable=self.save_password_var
        ).grid(row=2, column=1, columnspan=2, padx=5, pady=0, sticky='w') # Span to align
        
        # Remote directory
        ttk.Label(main_frame, text="Remote Directory:").grid(row=3, column=0, padx=5, pady=5, sticky='e') #
        self.directory_entry = ttk.Entry(main_frame, width=30) #
        self.directory_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky='ew') # Span to align
        if device_type == 'pi': #
            self.directory_entry.insert(0, default_directory or "/home/pi/") #
        else: #
            self.directory_entry.insert(0, default_directory or "/home/user/") #
        
        # Buttons
        button_frame = ttk.Frame(main_frame) #
        button_frame.grid(row=4, column=0, columnspan=3, pady=10) # Span all 3 columns
        
        ttk.Button(button_frame, text="Connect", command=self.ok, width=10).pack(side=tk.LEFT, padx=5) #
        ttk.Button(button_frame, text="Cancel", command=self.cancel, width=10).pack(side=tk.LEFT, padx=5) #
        
        # Configure column weights for main_frame if needed for better resizing
        main_frame.columnconfigure(1, weight=1) # Allow password entry to expand

        # Key bindings
        self.bind('<Return>', lambda e: self.ok()) #
        self.bind('<Escape>', lambda e: self.cancel()) #
        
        self.connection_entry.bind('<Return>', lambda e: self.password_entry.focus_set()) #
        self.password_entry.bind('<Return>', lambda e: self.directory_entry.focus_set()) #
        self.directory_entry.bind('<Return>', lambda e: self.ok()) #
        
        # Position and show dialog
        self.geometry(f"+{x}+{y}") #
        self.grab_set() #
        self.protocol("WM_DELETE_WINDOW", self.cancel) #
        
        # Get saved password if available
        self.load_saved_password() #

        # Set focus to connection entry if empty, else password if connection has value
        if not self.connection_entry.get():
            self.connection_entry.focus_set()
        elif not self.password_entry.get(): # If password was loaded, it might have focus from load_saved_password. This is fine.
            self.password_entry.focus_set()
        else: # If both are filled (e.g. from defaults and saved pass), focus password or connect button
            self.password_entry.focus_set()


    def toggle_password_visibility(self): #
        """Toggles the visibility of the password in the entry field."""
        if self.show_password_var.get(): #
            self.password_entry.config(show="") #
        else: #
            self.password_entry.config(show="*") #
        # --- Add this line to restore focus ---
        self.password_entry.focus_set()
    
    def load_saved_password(self): #
        """Try to load saved password for the connection"""
        try:
            connection = self.connection_entry.get().strip() #
            if '@' in connection: #
                username, hostname = connection.split('@', 1) #
                password = CredentialManager.get_credentials(hostname, username) #
                if password: #
                    self.password_entry.delete(0, tk.END) #
                    self.password_entry.insert(0, password) #
                    self.save_password_var.set(True) #
                    # Do not focus here, let __init__ handle final focus
        except Exception as e: # Catching generic exception to prevent dialog load failure
            logger.error(f"Error loading saved password: {e}")
            pass #
    
    def ok(self, event=None): #
        """Handle OK button"""
        connection = self.connection_entry.get().strip() #
        password = self.password_entry.get() #
        directory = self.directory_entry.get().strip() #
        save_password = self.save_password_var.get() #
        
        if not all([connection, password, directory]): #
            messagebox.showerror("Error", "All fields are required!") #
            return #
        
        try:
            username, hostname = connection.split('@', 1) #
        except ValueError: #
            messagebox.showerror("Error", "Invalid format. Please use 'username@hostname' format") #
            return #
        
        if not directory.endswith('/'): #
            directory += '/' #
        
        if save_password: #
            CredentialManager.save_credentials(hostname, username, password) #
        
        self.result = (hostname, username, password, directory, save_password) #
        self.destroy() #
    
    def cancel(self, event=None): #
        """Handle Cancel button"""
        self.result = None #
        self.destroy() #

class OverwriteDialog(tk.Toplevel):
    """Dialog for file overwrite confirmation"""
    def __init__(self, parent, filename):
        super().__init__(parent)
        self.title("File Exists")
        self.result = None
        self.transient(parent)
        self.attributes('-topmost', True)
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File info
        message = f"File '{filename}' already exists.\nWhat would you like to do?"
        ttk.Label(main_frame, text=message).pack(pady=10)
        
        # Buttons for actions
        for text, value in [
            ("Overwrite", "overwrite"),
            ("Skip", "skip"),
            ("Overwrite All", "overwrite_all"),
            ("Skip All", "skip_all"),
            ("Cancel", "cancel")
        ]:
            ttk.Button(
                main_frame,
                text=text,
                command=lambda v=value: self.set_result(v),
                width=20
            ).pack(pady=2)
        
        # Position dialog
        self.geometry(f"+{parent.winfo_rootx() + 50}+{parent.winfo_rooty() + 50}")
        
        # Keyboard shortcuts
        self.bind("<Return>", lambda e: self.set_result("overwrite"))
        self.bind("<Escape>", lambda e: self.set_result("cancel"))
        
        # Make modal
        self.grab_set()
        self.focus_force()
        self.lift()
        self.protocol("WM_DELETE_WINDOW", lambda: self.set_result("cancel"))
        
        # Wait for result
        parent.wait_window(self)
    
    def set_result(self, value):
        """Set the dialog result and close"""
        self.result = value
        self.grab_release()
        self.destroy()

class ProgressDialog(tk.Toplevel):
    """Dialog for showing file transfer progress"""
    def __init__(self, parent, total_size, total_files=1):
        super().__init__(parent)
        self.title("File Transfer Progress")
        self.transient(parent)
        
        self.total_size = total_size
        self.total_files = total_files
        self.cancel_flag = False
        self.start_time = time.time()
        self.rate_history = []
        
        # Thread-safe variables
        self._lock = threading.Lock()
        self._bytes_transferred = 0
        self._current_file = 1
        self._current_file_progress = {}  # Track progress per file
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Current file info
        file_info_frame = ttk.LabelFrame(main_frame, text="Current File")
        file_info_frame.pack(fill=tk.X, pady=5)
        
        self.filename_var = tk.StringVar(value="")
        ttk.Label(file_info_frame, textvariable=self.filename_var).pack(fill=tk.X, pady=5)
        
        self.file_progress = ttk.Progressbar(file_info_frame, mode='determinate', maximum=100)
        self.file_progress.pack(fill=tk.X, pady=5)
        
        self.file_status = tk.StringVar(value="")
        ttk.Label(file_info_frame, textvariable=self.file_status).pack(fill=tk.X)
        
        # Overall progress
        overall_frame = ttk.LabelFrame(main_frame, text="Overall Progress")
        overall_frame.pack(fill=tk.X, pady=10)
        
        self.total_progress = ttk.Progressbar(overall_frame, mode='determinate', maximum=100)
        self.total_progress.pack(fill=tk.X, pady=5)
        
        stats_frame = ttk.Frame(overall_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.total_status = tk.StringVar(value="")
        ttk.Label(stats_frame, textvariable=self.total_status).pack(side=tk.LEFT)
        
        self.time_left = tk.StringVar(value="")
        ttk.Label(stats_frame, textvariable=self.time_left).pack(side=tk.RIGHT)
        
        self.transfer_rate = tk.StringVar(value="")
        ttk.Label(overall_frame, textvariable=self.transfer_rate).pack(fill=tk.X, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="Cancel", command=self.cancel_transfer).pack(pady=5)
        
        # Configure dialog size and position
        self.geometry("450x350")
        self.geometry(f"+{parent.winfo_rootx() + 50}+{parent.winfo_rooty() + 50}")
        
        # DON'T use grab_set() - it causes problems with thread callbacks
        # self.grab_set()  # REMOVED - this was causing the hang!
        self.protocol("WM_DELETE_WINDOW", self.cancel_transfer)
        
        # Initialize counters
        self.last_update_time = time.time()
        self.last_bytes = 0
        
        # Start periodic UI update
        self._update_ui_periodically()
    
    @property
    def bytes_transferred(self):
        with self._lock:
            return self._bytes_transferred
    
    @bytes_transferred.setter
    def bytes_transferred(self, value):
        with self._lock:
            self._bytes_transferred = value
    
    @property
    def current_file(self):
        with self._lock:
            return self._current_file
    
    @current_file.setter
    def current_file(self, value):
        with self._lock:
            self._current_file = value
    
    def cancel_transfer(self):
        """Cancel the transfer operation"""
        self.cancel_flag = True
        self.file_status.set("Cancelling...")
        
    def update_file_progress(self, task):
        """Update progress for a specific file (thread-safe)"""
        with self._lock:
            self._current_file_progress[task.source_path] = {
                'current': task.bytes_transferred,
                'total': task.size,
                'filename': task.filename
            }
    
    def file_completed(self, task):
        """Mark a file as completed (thread-safe)"""
        with self._lock:
            self._bytes_transferred += task.size
            if task.source_path in self._current_file_progress:
                del self._current_file_progress[task.source_path]
            self._current_file = self._current_file + 1
    
    def _update_ui_periodically(self):
        """Update UI from main thread periodically"""
        if self.cancel_flag or not self.winfo_exists():
            return
        
        with self._lock:
            # Get current file being transferred
            if self._current_file_progress:
                # Show the first active file
                file_info = next(iter(self._current_file_progress.values()))
                filename = file_info['filename']
                current_size = file_info['current']
                total_size = file_info['total']
                
                self.filename_var.set(f"File {self._current_file} of {self.total_files}: {filename}")
                
                if total_size > 0:
                    pct = min(100, int((current_size * 100) / total_size))
                    self.file_progress['value'] = pct
                    self.file_status.set(f"{pct}% ({format_size(current_size)} of {format_size(total_size)})")
            
            # Update overall progress
            total_done = self._bytes_transferred
            # Add current progress of all active files
            for file_info in self._current_file_progress.values():
                total_done += file_info['current']
            
            if self.total_size > 0:
                overall_pct = min(100, int((total_done * 100) / self.total_size))
                self.total_progress['value'] = overall_pct
                self.total_status.set(
                    f"{overall_pct}% ({format_size(total_done)} of {format_size(self.total_size)})"
                )
            
            # Calculate transfer rate
            now = time.time()
            time_elapsed = now - self.start_time
            if time_elapsed > 0:
                rate = total_done / time_elapsed
                self.transfer_rate.set(f"Speed: {format_size(rate)}/s")
                
                if rate > 0 and total_done < self.total_size:
                    bytes_left = self.total_size - total_done
                    seconds_left = bytes_left / rate
                    self.time_left.set(f"Time left: {format_time(seconds_left)}")
        
        # Schedule next update
        self.after(100, self._update_ui_periodically)  # Update 10 times per second


class CreateDirDialog(tk.Toplevel):
    """Dialog for creating a new directory"""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Create Directory")
        self.result = None
        self.transient(parent)
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Enter new directory name:").pack(pady=(0,5))
        
        self.dir_name_var = tk.StringVar()
        entry = ttk.Entry(main_frame, textvariable=self.dir_name_var, width=30)
        entry.pack(pady=5)
        entry.focus_set()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=5)
        
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT, padx=5)
        
        # Keyboard shortcuts
        self.bind("<Return>", lambda e: self.on_ok())
        self.bind("<Escape>", lambda e: self.on_cancel())
        
        # Position dialog
        self.geometry(f"+{parent.winfo_rootx() + 50}+{parent.winfo_rooty() + 50}")
        
        # Make modal
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
    
    def on_ok(self):
        """Handle OK button"""
        name = self.dir_name_var.get().strip()
        if not name:
            messagebox.showwarning("Warning", "Directory name cannot be empty.")
            return
        
        # Check for invalid characters
        if '/' in name or '\\' in name or ':' in name or '*' in name or '?' in name or '"' in name or '<' in name or '>' in name or '|' in name:
            messagebox.showwarning("Warning", "Directory name cannot contain: / \\ : * ? \" < > |")
            return
        
        self.result = str(name)
        self.destroy()
    
    def on_cancel(self):
        """Handle Cancel button"""
        self.result = None
        self.destroy()

class FileSearchDialog(tk.Toplevel):
    """Dialog for searching files"""
    def __init__(self, parent, file_system_model, is_remote=False):
        super().__init__(parent)
        self.title("Search Files")
        self.result = None
        self.transient(parent)
        self.model = file_system_model
        self.is_remote = is_remote
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Search path
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Search in:").pack(side=tk.LEFT, padx=5)
        
        self.path_var = tk.StringVar(value=file_system_model.remote_directory if is_remote else file_system_model.local_directory)
        ttk.Entry(path_frame, textvariable=self.path_var, width=40).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(path_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT, padx=5)
        
        # Search criteria
        criteria_frame = ttk.LabelFrame(main_frame, text="Search Criteria")
        criteria_frame.pack(fill=tk.X, pady=10)
        
        # Filename pattern
        pattern_frame = ttk.Frame(criteria_frame)
        pattern_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Label(pattern_frame, text="Filename:").pack(side=tk.LEFT, padx=5)
        self.pattern_var = tk.StringVar()
        self.pattern_entry = ttk.Entry(pattern_frame, textvariable=self.pattern_var, width=30)
        self.pattern_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # File type
        type_frame = ttk.Frame(criteria_frame)
        type_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Label(type_frame, text="File Type:").pack(side=tk.LEFT, padx=5)
        self.type_var = tk.StringVar(value="both")
        ttk.Radiobutton(type_frame, text="Files", variable=self.type_var, value="file").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Directories", variable=self.type_var, value="dir").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(type_frame, text="Both", variable=self.type_var, value="both").pack(side=tk.LEFT, padx=5)
        
        # Size filter
        size_frame = ttk.Frame(criteria_frame)
        size_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Label(size_frame, text="Size:").pack(side=tk.LEFT, padx=5)
        self.size_op_var = tk.StringVar(value="any")
        ttk.Combobox(size_frame, textvariable=self.size_op_var, values=["any", ">", "<", "="], width=5).pack(side=tk.LEFT, padx=5)
        
        self.size_val_var = tk.StringVar()
        ttk.Entry(size_frame, textvariable=self.size_val_var, width=10).pack(side=tk.LEFT, padx=5)
        
        self.size_unit_var = tk.StringVar(value="MB")
        ttk.Combobox(size_frame, textvariable=self.size_unit_var, values=["B", "KB", "MB", "GB"], width=5).pack(side=tk.LEFT, padx=5)
        
        # Search depth
        depth_frame = ttk.Frame(criteria_frame)
        depth_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Label(depth_frame, text="Recursive:").pack(side=tk.LEFT, padx=5)
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(depth_frame, variable=self.recursive_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(depth_frame, text="Max Depth:").pack(side=tk.LEFT, padx=5)
        self.depth_var = tk.StringVar(value="")
        ttk.Entry(depth_frame, textvariable=self.depth_var, width=5).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Search", command=self.start_search, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel, width=10).pack(side=tk.LEFT, padx=5)
        
        # Results
        results_frame = ttk.LabelFrame(main_frame, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_tree = ttk.Treeview(
            results_frame,
            columns=('name', 'path', 'size', 'date'),
            show='headings',
            selectmode='extended'
        )
        self.results_tree.heading('name', text='Name')
        self.results_tree.heading('path', text='Path')
        self.results_tree.heading('size', text='Size')
        self.results_tree.heading('date', text='Date')
        
        self.results_tree.column('name', width=150, anchor='w')
        self.results_tree.column('path', width=250, anchor='w')
        self.results_tree.column('size', width=100, anchor='e')
        self.results_tree.column('date', width=150, anchor='w')
        
        # Add scrollbar
        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to search")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
        
        # Configure dialog size and position
        self.geometry("700x500")
        self.geometry(f"+{parent.winfo_rootx() + 50}+{parent.winfo_rooty() + 50}")
        
        # Bind events
        self.results_tree.bind('<Double-1>', self.on_result_double_click)
        self.bind('<Escape>', lambda e: self.cancel())
        
        # Make dialog non-modal so search can run in background
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.pattern_entry.focus_set()
    
    def browse_directory(self):
        """Browse for search directory"""
        if self.is_remote:
            messagebox.showinfo("Info", "Cannot browse remote directories directly")
            return
        
        path = filedialog.askdirectory(initialdir=self.path_var.get())
        if path:
            self.path_var.set(path)
    
    def start_search(self):
        """Start the search operation"""
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Get search parameters
        path = self.path_var.get()
        pattern = self.pattern_var.get()
        file_type = self.type_var.get()
        recursive = self.recursive_var.get()
        
        # Start search in a background thread
        self.status_var.set("Searching...")
        threading.Thread(target=self._search_worker, args=(path, pattern, file_type, recursive), daemon=True).start()
    
    def _search_worker(self, path, pattern, file_type, recursive):
        """Background worker for search"""
        try:
            results = []
            
            # Search function depends on local/remote
            if self.is_remote:
                if not self.model.is_connected:
                    self.update_status("Error: Not connected to remote system")
                    return
                
                results = self._search_remote(path, pattern, file_type, recursive)
            else:
                results = self._search_local(path, pattern, file_type, recursive)
            
            # Update UI with results
            self.update_results(results)
            
        except Exception as e:
            self.update_status(f"Error during search: {str(e)}")
    
    def _search_local(self, path, pattern, file_type, recursive, max_depth=10, current_depth=0):
        """Search local files"""
        results = []
        
        try:
            # Check depth limit
            if max_depth > 0 and current_depth >= max_depth:
                return results
            
            # Use pathlib for better file handling
            path_obj = Path(path)
            if not path_obj.exists():
                return results
            
            # Update status
            self.update_status(f"Searching: {path}")
            
            # Process each item in directory
            for entry in path_obj.iterdir():
                try:
                    # Skip hidden files/dirs unless specifically requested
                    if entry.name.startswith('.') and not pattern.startswith('.'):
                        continue
                    
                    is_dir = entry.is_dir()
                    
                    # Check file type filter
                    if file_type == 'file' and is_dir:
                        continue
                    elif file_type == 'dir' and not is_dir:
                        continue
                    
                    # Check name pattern
                    if pattern and pattern.lower() not in entry.name.lower():
                        if not pattern.startswith('*') or not pattern.endswith('*') or not self._match_wildcard(entry.name, pattern):
                            continue
                    
                    # Add to results if matched
                    try:
                        stat_info = entry.stat()
                        size = 0 if is_dir else stat_info.st_size
                        date = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        
                        results.append({
                            'name': entry.name,
                            'path': str(entry),
                            'size': format_size(size) if not is_dir else '',
                            'date': date,
                            'is_dir': is_dir
                        })
                    except (PermissionError, OSError):
                        continue
                    
                    # Recursively search subdirectories
                    if recursive and is_dir:
                        sub_results = self._search_local(
                            str(entry),
                            pattern,
                            file_type,
                            recursive,
                            max_depth,
                            current_depth + 1
                        )
                        results.extend(sub_results)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError) as e:
            self.update_status(f"Access error: {str(e)}")
        
        return results
    
    def _search_remote(self, path, pattern, file_type, recursive, max_depth=10, current_depth=0):
        """Search remote files"""
        results = []
        
        try:
            # Check depth limit
            if max_depth > 0 and current_depth >= max_depth:
                return results
            
            # Update status
            self.update_status(f"Searching remote: {path}")
            
            # List directory contents
            items = self.model.sftp.listdir_attr(path)
            
            for item in items:
                try:
                    name = item.filename
                    
                    # Skip hidden files/dirs unless specifically requested
                    if name.startswith('.') and not pattern.startswith('.'):
                        continue
                    
                    is_dir = stat.S_ISDIR(item.st_mode)
                    full_path = os.path.join(path, name).replace('\\', '/')
                    
                    # Check file type filter
                    if file_type == 'file' and is_dir:
                        continue
                    elif file_type == 'dir' and not is_dir:
                        continue
                    
                    # Check name pattern
                    if pattern and pattern.lower() not in name.lower():
                        if not pattern.startswith('*') or not pattern.endswith('*') or not self._match_wildcard(name, pattern):
                            continue
                    
                    # Add to results if matched
                    size = 0 if is_dir else item.st_size
                    date = datetime.fromtimestamp(item.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    
                    results.append({
                        'name': name,
                        'path': full_path,
                        'size': format_size(size) if not is_dir else '',
                        'date': date,
                        'is_dir': is_dir
                    })
                    
                    # Recursively search subdirectories
                    if recursive and is_dir:
                        sub_results = self._search_remote(
                            full_path,
                            pattern,
                            file_type,
                            recursive,
                            max_depth,
                            current_depth + 1
                        )
                        results.extend(sub_results)
                except Exception:
                    continue
        except Exception as e:
            self.update_status(f"Remote search error: {str(e)}")
        
        return results
    
    def _match_wildcard(self, name, pattern):
        """Simple wildcard matching for * patterns"""
        if not pattern or pattern == '*':
            return True
        
        if pattern.startswith('*') and pattern.endswith('*'):
            return pattern[1:-1].lower() in name.lower()
        elif pattern.startswith('*'):
            return name.lower().endswith(pattern[1:].lower())
        elif pattern.endswith('*'):
            return name.lower().startswith(pattern[:-1].lower())
        
        return False
    
    def update_status(self, message):
        """Update status message (thread-safe)"""
        if not self.winfo_exists():
            return
        self.status_var.set(message)
        self.update_idletasks()
    
    def update_results(self, results):
        """Update the results treeview (thread-safe)"""
        if not self.winfo_exists():
            return
        
        # Clear current results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Add new results
        for item in results:
            tags = ('directory',) if item['is_dir'] else ('file',)
            self.results_tree.insert('', 'end', values=(
                item['name'],
                item['path'],
                item['size'],
                item['date']
            ), tags=tags)
        
        self.update_status(f"Found {len(results)} items")
        
        # Configure row colors
        self.results_tree.tag_configure('directory', foreground='blue')
        self.results_tree.tag_configure('file', foreground='black')
    
    def on_result_double_click(self, event):
        """Handle double-click on search result"""
        item = self.results_tree.selection()[0]
        if not item:
            return
        
        values = self.results_tree.item(item)['values']
        path = values[1]
        
        # Set the result to the selected path
        self.result = path
        self.destroy()
    
    def cancel(self, event=None):
        """Cancel search and close dialog"""
        self.result = None
        self.destroy()

class FileTransfer:
    """Main file transfer application"""
    def __init__(self, master):
        self.master = master
        self.master.title("Universal File Transfer")
        self.master.geometry("1000x600")
        self.master.minsize(800, 500)
        
        # Create model
        self.model = FileSystemModel()
        
        # Set up UI
        self.active_panel = 'local'
        self.sort_order_local = {'name': False, 'extension': False, 'date': False}
        self.sort_order_remote = {'name': False, 'extension': False, 'date': False}
        # Store current sort key
        self.current_sort_key_local = 'name'
        self.current_sort_key_remote = 'name'
        self.local_selected_item = None
        self.remote_selected_item = None
        self.local_item_id_map = {}
        self.remote_item_id_map = {}
        
        # Create UI elements
        self.create_widgets()
        
        # Register keyboard shortcuts
        self.register_shortcuts()
        
        # Load initial data
        self.load_local_files()
        self.update_disk_info()
    
    def create_widgets(self):
        """Create all UI widgets"""
        # Main layout with menu
        self.create_menu()
        
        # Connection status frame
        self.create_connection_frame()
        
        # Navigation frame
        self.create_navigation_frame()
        
        # File panels
        self.create_file_panels()
        
        # Bottom button bar
        self.create_button_bar()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_menu(self):
        """Create application menu"""
        self.menu = tk.Menu(self.master)
        self.master.config(menu=self.menu)
        
        # File menu
        file_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Connect...", command=self.connect_to_remote)
        file_menu.add_command(label="Device List...", command=self.show_device_list)
        file_menu.add_command(label="Disconnect", command=self.disconnect_from_remote)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Operations menu
        ops_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Operations", menu=ops_menu)
        ops_menu.add_command(label="Upload Selected", command=self.upload_files)
        ops_menu.add_command(label="Download Selected", command=self.download_files)
        ops_menu.add_separator()
        ops_menu.add_command(label="Create Directory", command=self.create_directory)
        ops_menu.add_command(label="Delete Selected", command=lambda: self.delete_selected(None))
        ops_menu.add_command(label="Refresh", command=self.refresh_both)
        ops_menu.add_separator()
        ops_menu.add_command(label="Search Files...", command=self.search_files)
        
        # View menu
        view_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Sort by Name", command=lambda: self.sort_files(self.active_panel, 'name'))
        view_menu.add_command(label="Sort by Extension", command=lambda: self.sort_files(self.active_panel, 'extension'))
        view_menu.add_command(label="Sort by Date", command=lambda: self.sort_files(self.active_panel, 'date'))
        view_menu.add_separator()
        view_menu.add_command(label="Refresh Local", command=lambda: self.load_local_files(use_cache=False))
        view_menu.add_command(label="Refresh Remote", command=lambda: self.load_remote_files(use_cache=False))
        
        # Tools menu
        tools_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Compare Directories", command=self.compare_directories)
        tools_menu.add_command(label="Synchronize Directories", command=self.sync_directories)
        
        # Help menu
        help_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
    
    def create_connection_frame(self):
        """Create connection status and controls"""
        self.connection_frame = ttk.Frame(self.master)
        self.connection_frame.pack(padx=10, pady=5, fill=tk.X)
        
        # Connection status
        self.connection_status_label = ttk.Label(self.connection_frame, text="Not connected", foreground="red")
        self.connection_status_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Connect button
        self.connect_button = ttk.Button(
            self.connection_frame,
            text="Connect to Remote Device",
            width=25,
            command=self.connect_to_remote
        )
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        # Device list button
        self.device_list_button = ttk.Button(
            self.connection_frame,
            text="Device List",
            width=10,
            command=self.show_device_list
        )
        self.device_list_button.pack(side=tk.LEFT)
    
    def create_navigation_frame(self):
        """Create navigation controls"""
        self.nav_frame = ttk.Frame(self.master)
        self.nav_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Local path controls
        local_nav_frame = ttk.LabelFrame(self.nav_frame, text="Local Path")
        local_nav_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.local_path_var = tk.StringVar(value=self.model.local_directory)
        local_path_entry = ttk.Entry(local_nav_frame, textvariable=self.local_path_var)
        local_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        local_path_entry.bind('<Return>', self.on_local_path_enter)
        
        ttk.Button(local_nav_frame, text="Browse", command=self.browse_local_directory).pack(side=tk.LEFT, padx=5)
        
        # Remote path controls
        remote_nav_frame = ttk.LabelFrame(self.nav_frame, text="Remote Path")
        remote_nav_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.remote_path_var = tk.StringVar(value=self.model.remote_directory or "Not connected")
        remote_path_entry = ttk.Entry(remote_nav_frame, textvariable=self.remote_path_var)
        remote_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        remote_path_entry.bind('<Return>', self.on_remote_path_enter)
    
    def create_file_panels(self):
        """Create file browser panels"""
        # Create horizontal pane for file panels
        paned = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Define columns for file trees
        columns = ('name', 'extension', 'date', 'size')
        
        # Local file panel
        self.local_frame = ttk.Labelframe(paned, text="Local Device")
        paned.add(self.local_frame, weight=1)
        
        # Local disk info
        self.local_disk_label = ttk.Label(self.local_frame, text="Volume: N/A  Free: N/A", anchor='w')
        self.local_disk_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
        
        # Local file tree
        local_tree_frame = ttk.Frame(self.local_frame)
        local_tree_frame.pack(fill=tk.BOTH, expand=True)
        local_tree_frame.columnconfigure(0, weight=1)
        local_tree_frame.rowconfigure(0, weight=1)
        
        self.local_tree = ttk.Treeview(
            local_tree_frame,
            columns=columns,
            show='headings',
            selectmode='extended'
        )
        
        self.local_tree.heading('name', text='Name', command=lambda: self.sort_files('local', 'name'))
        self.local_tree.heading('extension', text='Extension', command=lambda: self.sort_files('local', 'extension'))
        self.local_tree.heading('date', text='Date', command=lambda: self.sort_files('local', 'date'))
        self.local_tree.heading('size', text='Size')
        
        self.local_tree.column('name', width=200, anchor='w')
        self.local_tree.column('extension', width=70, anchor='w')
        self.local_tree.column('date', width=150, anchor='w')
        self.local_tree.column('size', width=100, anchor='e')
        
        self.local_tree.grid(row=0, column=0, sticky='nsew')
        
        local_scrollbar = ttk.Scrollbar(local_tree_frame, orient=tk.VERTICAL, command=self.local_tree.yview)
        local_scrollbar.grid(row=0, column=1, sticky='ns')
        self.local_tree.configure(yscrollcommand=local_scrollbar.set)
        
        self.local_tree.tag_configure('directory', foreground='blue')
        self.local_tree.tag_configure('file', foreground='black')
        
        # Local tree events
        self.local_tree.bind('<Double-1>', lambda e: self.on_double_click('local'))
        self.local_tree.bind('<Return>', lambda e: self.on_double_click('local'))
        self.local_tree.bind('<Delete>', lambda e: self.delete_selected('local'))
        self.local_tree.bind('<Button-1>', lambda e: self.set_active_panel('local'))
        self.local_tree.bind('<<TreeviewSelect>>', self.on_local_selection)
        
        # Remote file panel
        self.remote_frame = ttk.Labelframe(paned, text="Remote Device")
        paned.add(self.remote_frame, weight=1)
        
        # Remote disk info
        self.remote_disk_label = ttk.Label(self.remote_frame, text="Volume: N/A  Free: N/A", anchor='w')
        self.remote_disk_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=2)
        
        # Remote file tree
        remote_tree_frame = ttk.Frame(self.remote_frame)
        remote_tree_frame.pack(fill=tk.BOTH, expand=True)
        remote_tree_frame.columnconfigure(0, weight=1)
        remote_tree_frame.rowconfigure(0, weight=1)
        
        self.remote_tree = ttk.Treeview(
            remote_tree_frame,
            columns=columns,
            show='headings',
            selectmode='extended'
        )
        
        self.remote_tree.heading('name', text='Name', command=lambda: self.sort_files('remote', 'name'))
        self.remote_tree.heading('extension', text='Extension', command=lambda: self.sort_files('remote', 'extension'))
        self.remote_tree.heading('date', text='Date', command=lambda: self.sort_files('remote', 'date'))
        self.remote_tree.heading('size', text='Size')
        
        self.remote_tree.column('name', width=200, anchor='w')
        self.remote_tree.column('extension', width=70, anchor='w')
        self.remote_tree.column('date', width=150, anchor='w')
        self.remote_tree.column('size', width=100, anchor='e')
        
        self.remote_tree.grid(row=0, column=0, sticky='nsew')
        
        remote_scrollbar = ttk.Scrollbar(remote_tree_frame, orient=tk.VERTICAL, command=self.remote_tree.yview)
        remote_scrollbar.grid(row=0, column=1, sticky='ns')
        self.remote_tree.configure(yscrollcommand=remote_scrollbar.set)
        
        self.remote_tree.tag_configure('directory', foreground='blue')
        self.remote_tree.tag_configure('file', foreground='black')
        
        # Remote tree events
        self.remote_tree.bind('<Double-1>', lambda e: self.on_double_click('remote'))
        self.remote_tree.bind('<Return>', lambda e: self.on_double_click('remote'))
        self.remote_tree.bind('<Delete>', lambda e: self.delete_selected('remote'))
        self.remote_tree.bind('<Button-1>', lambda e: self.set_active_panel('remote'))
        self.remote_tree.bind('<<TreeviewSelect>>', self.on_remote_selection)
    
    def create_button_bar(self):
        """Create bottom button bar"""
        self.button_frame = ttk.Frame(self.master)
        self.button_frame.pack(pady=10)
        
        ttk.Button(self.button_frame, text="Upload", command=self.upload_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Download", command=self.download_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Create Dir", command=self.create_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Delete", command=lambda: self.delete_selected(None)).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Refresh", command=self.refresh_both).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.button_frame, text="Exit", command=self.on_closing).pack(side=tk.LEFT, padx=5)
    
    def register_shortcuts(self):
        """Register keyboard shortcuts"""
        self.master.bind('<Tab>', self.switch_active_panel)
        self.master.bind('<F2>', lambda e: self.refresh_both())
        self.master.bind('<F5>', lambda e: self.refresh_both())
        self.master.bind('<F3>', lambda e: self.search_files())
        self.master.bind('<Control-n>', lambda e: self.create_directory())
        self.master.bind('<Control-c>', lambda e: self.copy_selected_path())
        self.master.bind('<Control-q>', lambda e: self.on_closing())
        
        # Transfer shortcuts
        self.master.bind('<F6>', lambda e: self.upload_files())
        self.master.bind('<F7>', lambda e: self.download_files())
    
    def switch_active_panel(self, event=None):
        """Switch between local and remote panels"""
        if self.active_panel == 'local':
            self.set_active_panel('remote')
        else:
            self.set_active_panel('local')
        return 'break'
    
    def on_local_selection(self, event):
        """Handle local file selection"""
        self.local_selected_item = self.local_tree.selection()
        if self.active_panel != 'local':
            self.local_tree.selection_remove(self.local_selected_item)
    
    def on_remote_selection(self, event):
        """Handle remote file selection"""
        self.remote_selected_item = self.remote_tree.selection()
        if self.active_panel != 'remote':
            self.remote_tree.selection_remove(self.remote_selected_item)
    
    def set_active_panel(self, panel):
        """Set the active panel (local or remote)"""
        if panel == self.active_panel:
            return
        
        # Save current selection
        if self.active_panel == 'local':
            self.local_selected_item = self.local_tree.selection()
            self.local_tree.selection_remove(self.local_tree.selection())
        else:
            self.remote_selected_item = self.remote_tree.selection()
            self.remote_tree.selection_remove(self.remote_tree.selection())
        
        # Update active panel
        self.active_panel = panel
        
        # Restore selection
        if panel == 'local':
            if self.local_selected_item:
                self.local_tree.selection_set(self.local_selected_item)
                self.local_tree.focus(self.local_selected_item[0])
            else:
                if '..' in self.local_item_id_map:
                    self.local_selected_item = (self.local_item_id_map['..'],)
                    self.local_tree.selection_set(self.local_selected_item)
                    self.local_tree.focus(self.local_selected_item[0])
            self.local_tree.focus_set()
        else:
            if self.remote_selected_item:
                self.remote_tree.selection_set(self.remote_selected_item)
                self.remote_tree.focus(self.remote_selected_item[0])
            else:
                if '..' in self.remote_item_id_map:
                    self.remote_selected_item = (self.remote_item_id_map['..'],)
                    self.remote_tree.selection_set(self.remote_selected_item)
                    self.remote_tree.focus(self.remote_selected_item[0])
            self.remote_tree.focus_set()
        
        # Update status
        self.status_var.set(f"Active panel: {'Local' if panel == 'local' else 'Remote'}")
    
    def on_local_path_enter(self, event):
        """Handle Enter key in local path entry"""
        new_path = self.local_path_var.get()
        if os.path.exists(new_path) and os.path.isdir(new_path):
            self.model.local_directory = normalize_path(new_path)
            self.local_path_var.set(self.model.local_directory)
            self.load_local_files()
        else:
            messagebox.showerror("Error", f"Invalid directory: {new_path}")
            self.local_path_var.set(self.model.local_directory)
    
    def on_remote_path_enter(self, event):
        """Handle Enter key in remote path entry"""
        if not self.model.is_connected:
            messagebox.showwarning("Warning", "Not connected to remote device")
            return
        
        new_path = self.remote_path_var.get()
        try:
            # Check if path exists and is a directory
            self.model.sftp.stat(new_path)
            self.model.remote_directory = normalize_path(new_path, is_remote=True)
            self.remote_path_var.set(self.model.remote_directory)
            self.load_remote_files()
        except FileNotFoundError:
            messagebox.showerror("Error", f"Remote directory not found: {new_path}")
            self.remote_path_var.set(self.model.remote_directory or "Not connected")
        except PermissionError:
            messagebox.showerror("Error", f"Access denied to remote directory: {new_path}")
            self.remote_path_var.set(self.model.remote_directory or "Not connected")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid remote directory: {str(e)}")
            self.remote_path_var.set(self.model.remote_directory or "Not connected")
    
    def browse_local_directory(self):
        """Browse for local directory"""
        new_dir = filedialog.askdirectory(initialdir=self.model.local_directory)
        if new_dir:
            self.model.local_directory = normalize_path(new_dir)
            self.local_path_var.set(self.model.local_directory)
            self.load_local_files()
    
    def update_disk_info(self):
        """Update disk information displays"""
        try:
            # Update local disk info
            local_info = self.model.get_local_disk_info()
            if local_info:
                info_text = f"Volume: {local_info['volume']}  Free: {format_size(local_info['free'])} of {format_size(local_info['total'])}"
                self.local_disk_label.config(text=info_text)
            else:
                self.local_disk_label.config(text="Volume: N/A  Free: N/A")
            
            # Update remote disk info
            remote_info = self.model.get_remote_disk_info()
            if remote_info:
                info_text = f"Volume: {remote_info['volume']}  Free: {format_size(remote_info['free'])} of {format_size(remote_info['total'])}"
                self.remote_disk_label.config(text=info_text)
            else:
                self.remote_disk_label.config(text="Volume: N/A  Free: N/A")
        except Exception as e:
            logger.error(f"Error updating disk info: {str(e)}")
    
    def load_local_files(self, use_cache=True):
        """Load files from local directory"""
        try:
            files = self.model.get_local_files(use_cache=use_cache)
            
            # Convert to display format and sort
            self.file_list = []
            for file_item in files:
                item_type = 'directory' if file_item.is_dir else 'file'
                self.file_list.append((
                    file_item.name,
                    file_item.extension,
                    file_item.formatted_date,
                    file_item.formatted_size,
                    item_type
                ))
            
            # Apply current sort
            self.sort_files('local', self.current_sort_key_local, preserve_order=True)
            self.update_disk_info()
            
        except FileNotFoundError:
            messagebox.showerror("Error", f"Directory not found: {self.model.local_directory}")
            # Try parent directory
            parent = os.path.dirname(self.model.local_directory)
            if parent != self.model.local_directory:
                self.model.local_directory = normalize_path(parent)
                self.local_path_var.set(self.model.local_directory)
                self.load_local_files()
            
        except PermissionError:
            messagebox.showerror("Error", f"Access denied to {self.model.local_directory}")
            # Try parent directory
            parent = os.path.dirname(self.model.local_directory)
            if parent != self.model.local_directory:
                self.model.local_directory = normalize_path(parent)
                self.local_path_var.set(self.model.local_directory)
                self.load_local_files()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load local files: {str(e)}")
    
    def load_remote_files(self, use_cache=True):
        """Load files from remote directory"""
        if not self.model.is_connected:
            self.remote_file_list = []
            self.update_file_tree('remote')
            return
        
        try:
            files = self.model.get_remote_files(use_cache=use_cache)
            
            # Convert to display format and sort
            self.remote_file_list = []
            for file_item in files:
                item_type = 'directory' if file_item.is_dir else 'file'
                self.remote_file_list.append((
                    file_item.name,
                    file_item.extension,
                    file_item.formatted_date,
                    file_item.formatted_size,
                    item_type
                ))
            
            # Apply current sort
            self.sort_files('remote', self.current_sort_key_remote, preserve_order=True)
            self.update_disk_info()
            
        except FileNotFoundError:
            messagebox.showerror("Error", f"Remote directory not found: {self.model.remote_directory}")
            # Try parent directory
            if self.model.remote_directory != '/':
                parent = os.path.dirname(self.model.remote_directory.rstrip('/'))
                self.model.remote_directory = normalize_path(parent, is_remote=True)
                self.remote_path_var.set(self.model.remote_directory)
                self.load_remote_files()
            
        except PermissionError:
            messagebox.showerror("Error", f"Access denied to remote directory: {self.model.remote_directory}")
            # Try parent directory
            if self.model.remote_directory != '/':
                parent = os.path.dirname(self.model.remote_directory.rstrip('/'))
                self.model.remote_directory = normalize_path(parent, is_remote=True)
                self.remote_path_var.set(self.model.remote_directory)
                self.load_remote_files()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load remote files: {str(e)}")
    
    def sort_files(self, target, key, preserve_order=False):
        """Sort file list by column"""
        if target == 'local':
            sort_order = self.sort_order_local
            file_list = self.file_list
            tree = self.local_tree
            # Update current sort key
            if not preserve_order:
                self.current_sort_key_local = key
        elif target == 'remote':
            sort_order = self.sort_order_remote
            file_list = self.remote_file_list
            tree = self.remote_tree
            # Update current sort key
            if not preserve_order:
                self.current_sort_key_remote = key
        else:
            return
        
        # Toggle sort order only if not preserving order
        if not preserve_order:
            sort_order[key] = not sort_order[key]
        reverse = sort_order[key]
        
        # Separate parent directory from regular files
        parent_dir = next((item for item in file_list if item[0] == '..'), None)
        regular_files = [item for item in file_list if item[0] != '..']
        
        # Sort by selected column
        if key == 'name':
            regular_files.sort(key=lambda x: (x[-1] != 'directory', x[0].lower()), reverse=reverse)
        elif key == 'extension':
            regular_files.sort(key=lambda x: (x[-1] != 'directory', x[1].lower()), reverse=reverse)
        elif key == 'date':
            regular_files.sort(key=lambda x: (x[-1] != 'directory', x[2]), reverse=reverse)
        
        # Rebuild file list with parent directory first
        file_list[:] = ([parent_dir] if parent_dir else []) + regular_files
        
        # Update display
        self.update_file_tree(target)
        self.update_column_headings(tree, key, reverse)
    
    def update_column_headings(self, tree, sorted_key, reverse):
        """Update column headings with sort indicators"""
        up_arrow = ' ▲'
        down_arrow = ' ▼'
        columns = ['name', 'extension', 'date']
        
        for col in columns:
            heading_text = col.capitalize()
            if col == sorted_key:
                arrow = down_arrow if reverse else up_arrow
                tree.heading(col, text=heading_text + arrow)
            else:
                tree.heading(col, text=heading_text)
    
    def update_file_tree(self, target):
        """Update file treeview content"""
        if target == 'local':
            tree = self.local_tree
            file_list = self.file_list
        elif target == 'remote':
            tree = self.remote_tree
            file_list = self.remote_file_list
        else:
            return
        
        # Clear current items
        tree.delete(*tree.get_children())
        
        # Map for item identifiers
        item_id_map = {}
        
        # Add items to tree
        for item in file_list:
            tags = ('directory',) if item[0] == '..' or item[-1] == 'directory' else ('file',)
            item_id = tree.insert('', 'end', values=item[:-1], tags=tags)
            item_id_map[item[0]] = item_id
        
        # Store item map
        if target == 'local':
            self.local_item_id_map = item_id_map
        else:
            self.remote_item_id_map = item_id_map
        
        # Update selection
        self.update_selection(target)
    
    def update_selection(self, target):
        """Update selection after tree update"""
        if target == 'local':
            tree = self.local_tree
            selected_item = self.local_selected_item
            item_id_map = self.local_item_id_map
        elif target == 'remote':
            tree = self.remote_tree
            selected_item = self.remote_selected_item
            item_id_map = self.remote_item_id_map
        else:
            return
        
        # Check if previous selection still exists
        if not selected_item or not any(item in tree.get_children() for item in selected_item):
            if '..' in item_id_map:
                selected_item = (item_id_map['..'],)
            else:
                children = tree.get_children()
                if children:
                    selected_item = (children[0],)
                else:
                    selected_item = None
        
        # Store updated selection
        if target == 'local':
            self.local_selected_item = selected_item
        else:
            self.remote_selected_item = selected_item
        
        # Apply selection if this is the active panel
        if self.active_panel == target and selected_item:
            tree.selection_set(selected_item)
            tree.focus(selected_item[0])
            tree.focus_set()
        else:
            tree.selection_remove(tree.selection())
    
    def on_double_click(self, target):
        """Handle double-click on file/directory"""
        try:
            if target == 'local':
                selected = self.local_tree.selection()
                if not selected:
                    return
                
                item = selected[0]
                values = self.local_tree.item(item)['values']
                if not values:
                    return
                
                if values[0] == '..':
                    # Navigate to parent directory
                    parent = os.path.dirname(self.model.local_directory)
                    if parent != self.model.local_directory and os.path.exists(parent):
                        self.model.local_directory = normalize_path(parent)
                        self.local_path_var.set(self.model.local_directory)
                        self.local_selected_item = None
                        self.load_local_files()
                        self.local_tree.focus_set()
                
                elif 'directory' in self.local_tree.item(item)['tags']:
                    # Navigate to subdirectory
                    dir_name = str(values[0])
                    new_path = os.path.join(self.model.local_directory, dir_name)
                    
                    if os.path.exists(new_path):
                        self.model.local_directory = normalize_path(new_path)
                        self.local_path_var.set(self.model.local_directory)
                        self.local_selected_item = None
                        self.load_local_files()
                        self.local_tree.focus_set()
                    else:
                        messagebox.showerror("Error", f"Directory not found: {new_path}")
                        self.load_local_files()
            
            elif target == 'remote' and self.model.is_connected:
                selected = self.remote_tree.selection()
                if not selected:
                    return
                
                item = selected[0]
                values = self.remote_tree.item(item)['values']
                if not values:
                    return
                
                if values[0] == '..':
                    # Navigate to parent directory
                    parent = os.path.dirname(self.model.remote_directory.rstrip('/'))
                    if parent != self.model.remote_directory:
                        self.model.remote_directory = normalize_path(parent, is_remote=True)
                        self.remote_path_var.set(self.model.remote_directory)
                        self.remote_selected_item = None
                        self.load_remote_files()
                        self.remote_tree.focus_set()
                
                elif 'directory' in self.remote_tree.item(item)['tags']:
                    # Navigate to subdirectory
                    dir_name = str(values[0])
                    new_path = os.path.join(self.model.remote_directory, dir_name).replace('\\', '/')
                    
                    try:
                        self.model.sftp.listdir(new_path)
                        self.model.remote_directory = normalize_path(new_path, is_remote=True)
                        self.remote_path_var.set(self.model.remote_directory)
                        self.remote_selected_item = None
                        self.load_remote_files()
                        self.remote_tree.focus_set()
                    except (IOError, FileNotFoundError) as e:
                        messagebox.showerror("Error", f"Cannot access directory: {str(e)}")
                        self.load_remote_files()
        
        except Exception as e:
            messagebox.showerror("Error", f"Navigation error: {str(e)}")
    
    def show_device_list(self):
        """Show device selection dialog"""
        try:
            # Position dialog near button
            x = self.device_list_button.winfo_rootx()
            y = self.device_list_button.winfo_rooty() + self.device_list_button.winfo_height()
            
            # Show device list dialog
            device_dialog = DeviceListDialog(self.master, x, y)
            self.master.wait_window(device_dialog)
            
            if device_dialog.result:
                # Get connection info for selected device
                device_info = device_dialog.result
                
                # Get saved password if available
                if '@' in device_info['connection']:
                    username, hostname = device_info['connection'].split('@', 1)
                    saved_password = CredentialManager.get_credentials(hostname, username)
                    
                    if saved_password:
                        # Connect directly with saved credentials
                        try:
                            self.connect_to_remote_with_credentials(
                                hostname,
                                username,
                                saved_password,
                                device_info['directory'],
                                device_type=device_info['type'],
                                device_name=device_info.get('name')
                            )
                            return
                        except AuthenticationError:
                            # If auth fails, continue to show password dialog
                            pass
                
                # Show connection dialog with device info
                conn_x = self.connect_button.winfo_rootx()
                conn_y = self.connect_button.winfo_rooty() + self.connect_button.winfo_height()
                
                conn_dialog = ConnectionDialog(
                    self.master,
                    conn_x, conn_y,
                    device_type=device_info['type'],
                    default_connection=device_info.get('connection'),
                    default_directory=device_info.get('directory')
                )
                
                self.master.wait_window(conn_dialog)
                
                if conn_dialog.result:
                    hostname, username, password, dest_dir, save_password = conn_dialog.result
                    
                    self.connect_to_remote_with_credentials(
                        hostname,
                        username,
                        password,
                        dest_dir,
                        device_type=device_info['type'],
                        device_name=device_info.get('name')
                    )
        
        except Exception as e:
            logger.error(f"Error in show_device_list: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def connect_to_remote_with_credentials(self, hostname, username, password, dest_dir, device_type='pc', device_name=None):
        """Connect to remote device with provided credentials"""
        try:
            # Show connection status
            self.status_var.set(f"Connecting to {hostname}...")
            self.master.update_idletasks()
            
            # Connect to remote system
            self.model.connect(
                hostname=hostname,
                username=username,
                password=password,
                directory=dest_dir,
                device_type=device_type,
                device_name=device_name
            )
            
            # Update UI after successful connection
            display_name = device_name or f"{username}@{hostname}"
            self.status_var.set(f"Connected to {display_name}")
            self.connection_status_label.config(text=f"Connected to: {display_name}", foreground="green")
            self.remote_path_var.set(self.model.remote_directory)
            self.connect_button.config(text="Disconnect", command=self.disconnect_from_remote)
            
            # Load remote files
            self.load_remote_files()
            self.update_disk_info()
            
        except AuthenticationError as e:
            logger.error(f"Authentication failed: {str(e)}")
            messagebox.showerror("Connection Error", str(e))
            
        except ConnectionError as e:
            logger.error(f"Connection error: {str(e)}")
            messagebox.showerror("Connection Error", str(e))
            
        except Exception as e:
            logger.error(f"Unexpected error during connection: {str(e)}", exc_info=True)
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
    
    def connect_to_remote(self):
        """Show connection dialog for direct connection"""
        if self.model.is_connected:
            messagebox.showinfo("Info", "Already connected to remote device.")
            return
        
        logger.info("Starting direct connection process...")
        
        # Position dialog
        x = self.connect_button.winfo_rootx()
        y = self.connect_button.winfo_rooty() + self.connect_button.winfo_height()
        
        # Show connection dialog
        dialog = ConnectionDialog(self.master, x, y, device_type='pc')
        self.master.wait_window(dialog)
        
        if dialog.result:
            hostname, username, password, dest_dir, save_password = dialog.result
            self.connect_to_remote_with_credentials(hostname, username, password, dest_dir, device_type='pc')
    
    def disconnect_from_remote(self):
        """Disconnect from remote device"""
        if not self.model.is_connected:
            return
        
        try:
            self.model.disconnect()
            device_type = self.model.device_type or "device"
            
            logger.info(f"Disconnected from remote {device_type}")
            messagebox.showinfo("Disconnected", f"Disconnected from remote {device_type}.")
            
            # Update UI
            self.connection_status_label.config(text="Not connected", foreground="red")
            self.connect_button.config(text="Connect to Remote Device", command=self.connect_to_remote)
            self.remote_path_var.set("Not connected")
            self.remote_file_list = []
            self.update_file_tree('remote')
            self.remote_disk_label.config(text="Volume: N/A  Free: N/A")
            
            self.status_var.set("Disconnected from remote device")
            
        except Exception as e:
            logger.error(f"Error during disconnect: {str(e)}")
            messagebox.showerror("Error", f"Error during disconnect: {str(e)}")
                
    def upload_files(self):
        """Upload selected files to remote device"""
        if not self.model.is_connected:
            messagebox.showwarning("Warning", "Not connected to remote device.")
            return
        
        # Get selection from the correct tree regardless of active panel
        selected_items = self.local_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "No files selected for upload!")
            return
        
        try:
            # Collect files to transfer
            files_to_transfer = []
            total_size = 0
            
            # Process all selected items
            for item in selected_items:
                values = self.local_tree.item(item)['values']
                if values[0] == '..':
                    continue
                
                if 'directory' in self.local_tree.item(item)['tags']:
                    # Handle directory upload
                    dir_name = str(values[0])
                    local_dir_path = os.path.join(self.model.local_directory, dir_name)
                    remote_dir_path = os.path.join(self.model.remote_directory, dir_name).replace('\\', '/')
                    
                    # Walk directory tree and collect files
                    for root, dirs, files in os.walk(local_dir_path):
                        rel_part = os.path.relpath(root, local_dir_path).replace('\\', '/')
                        if rel_part == '.':
                            remote_subdir = remote_dir_path
                        else:
                            remote_subdir = os.path.join(remote_dir_path, rel_part).replace('\\', '/')
                        
                        # Add all files in this directory
                        for f in files:
                            full_local_file = os.path.join(root, f)
                            full_remote_file = os.path.join(remote_subdir, f).replace('\\', '/')
                            
                            try:
                                size = os.path.getsize(full_local_file)
                                total_size += size
                                files_to_transfer.append((full_local_file, full_remote_file, size))
                            except Exception as e:
                                logger.error(f"Error getting file info for {full_local_file}: {str(e)}")
                
                else:
                    # Handle single file upload
                    filename = str(values[0])
                    
                    local_path = os.path.join(self.model.local_directory, filename)
                    remote_path = os.path.join(self.model.remote_directory, filename).replace('\\', '/')
                    
                    if os.path.isfile(local_path):
                        size = os.path.getsize(local_path)
                        total_size += size
                        files_to_transfer.append((local_path, remote_path, size))
            
            # Check if any files to transfer
            if not files_to_transfer:
                messagebox.showinfo("Info", "No files to upload.")
                return
            
            # Check disk space on remote system
            remote_info = self.model.get_remote_disk_info()
            if remote_info and remote_info['free'] < total_size:
                if not messagebox.askyesno(
                    "Warning",
                    f"Not enough space on remote device.\nRequired: {format_size(total_size)}\nAvailable: {format_size(remote_info['free'])}\n\nContinue anyway?"
                ):
                    return
            
            # Show progress dialog (non-modal)
            progress_dialog = ProgressDialog(self.master, total_size, len(files_to_transfer))
            
            # Configure transfer manager callbacks
            transfer_manager = self.model.transfer_manager
            transfer_manager.overwrite_all = False
            transfer_manager.skip_all = False
            
            # Clear previous callbacks
            transfer_manager.callbacks = {
                'progress': [],
                'file_complete': [],
                'all_complete': [],
                'error': []
            }
            
            # Add callbacks with the new thread-safe progress dialog
            transfer_manager.add_callback('progress', lambda task: progress_dialog.update_file_progress(task))
            transfer_manager.add_callback('file_complete', lambda task: progress_dialog.file_completed(task))
            transfer_manager.add_callback('all_complete', lambda: self.on_transfer_complete(progress_dialog))
            
            # Process files
            for local_path, remote_path, size in files_to_transfer:
                # Check for file existence
                file_exists = False
                try:
                    self.model.sftp.stat(remote_path)
                    file_exists = True
                except FileNotFoundError:
                    file_exists = False
                
                # Handle file overwrite
                if file_exists:
                    if transfer_manager.overwrite_all:
                        proceed = True
                    elif transfer_manager.skip_all:
                        continue
                    else:
                        filename = os.path.basename(local_path)
                        action = OverwriteDialog(self.master, filename).result
                        
                        if action == "cancel":
                            progress_dialog.cancel_transfer()
                            break
                        elif action == "skip":
                            continue
                        elif action == "skip_all":
                            transfer_manager.skip_all = True
                            continue
                        elif action == "overwrite_all":
                            transfer_manager.overwrite_all = True
                            proceed = True
                        elif action == "overwrite":
                            proceed = True
                        else:
                            continue
                else:
                    proceed = True
                
                # Create transfer task
                if proceed:
                    task = FileTransferTask(local_path, remote_path, size, is_upload=True)
                    transfer_manager.add_task(task)
            
            # Start transfer workers
            transfer_manager.start_workers()
            
        except Exception as e:
            messagebox.showerror("Error", f"Upload operation failed: {str(e)}")
            logger.error(f"Upload operation failed: {str(e)}", exc_info=True)


    def download_files(self):
        """Download selected files from remote device"""
        if not self.model.is_connected:
            messagebox.showwarning("Warning", "Not connected to remote device.")
            return
        
        # Get selection from the correct tree regardless of active panel
        selected_items = self.remote_tree.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "No files selected for download!")
            return
        
        try:
            # Collect files to transfer
            files_to_transfer = []
            total_size = 0
            
            # Process all selected items
            for item in selected_items:
                values = self.remote_tree.item(item)['values']
                if values[0] == '..':
                    continue
                
                if 'directory' in self.remote_tree.item(item)['tags']:
                    # Handle directory download
                    dir_name = str(values[0])
                    remote_dir_path = os.path.join(self.model.remote_directory, dir_name).replace('\\', '/')
                    local_dir_path = os.path.join(self.model.local_directory, dir_name)
                    
                    # Walk remote directory tree and collect files
                    for root, dirs, files in walk_remote_dir(self.model.sftp, remote_dir_path):
                        rel_part = os.path.relpath(root, remote_dir_path).replace('\\', '/')
                        if rel_part == '.':
                            local_subdir = local_dir_path
                        else:
                            local_subdir = os.path.join(local_dir_path, rel_part)
                        
                        # Add all files in this directory
                        for f in files:
                            full_remote_file = os.path.join(root, f).replace('\\', '/')
                            full_local_file = os.path.join(local_subdir, f)
                            
                            try:
                                attrs = self.model.sftp.stat(full_remote_file)
                                size = attrs.st_size
                                total_size += size
                                files_to_transfer.append((full_remote_file, full_local_file, size))
                            except Exception as e:
                                logger.error(f"Error getting file info for {full_remote_file}: {str(e)}")
                
                else:
                    # Handle single file download
                    filename = str(values[0])
                    
                    remote_path = os.path.join(self.model.remote_directory, filename).replace('\\', '/')
                    local_path = os.path.join(self.model.local_directory, filename)
                    
                    try:
                        attrs = self.model.sftp.stat(remote_path)
                        if stat.S_ISREG(attrs.st_mode):  # Regular file
                            size = attrs.st_size
                            total_size += size
                            files_to_transfer.append((remote_path, local_path, size))
                    except Exception as e:
                        logger.error(f"Error getting info for {filename}: {str(e)}")
            
            # Check if any files to transfer
            if not files_to_transfer:
                messagebox.showinfo("Info", "No files to download.")
                return
            
            # Check disk space on local system
            local_info = self.model.get_local_disk_info()
            if local_info and local_info['free'] < total_size:
                if not messagebox.askyesno(
                    "Warning",
                    f"Not enough space on local device.\nRequired: {format_size(total_size)}\nAvailable: {format_size(local_info['free'])}\n\nContinue anyway?"
                ):
                    return
            
            # Show progress dialog (non-modal)
            progress_dialog = ProgressDialog(self.master, total_size, len(files_to_transfer))
            
            # Configure transfer manager callbacks
            transfer_manager = self.model.transfer_manager
            transfer_manager.overwrite_all = False
            transfer_manager.skip_all = False
            
            # Clear previous callbacks
            transfer_manager.callbacks = {
                'progress': [],
                'file_complete': [],
                'all_complete': [],
                'error': []
            }
            
            # Add callbacks with the new thread-safe progress dialog
            transfer_manager.add_callback('progress', lambda task: progress_dialog.update_file_progress(task))
            transfer_manager.add_callback('file_complete', lambda task: progress_dialog.file_completed(task))
            transfer_manager.add_callback('all_complete', lambda: self.on_transfer_complete(progress_dialog))
            
            # Process files
            for remote_path, local_path, size in files_to_transfer:
                # Check for file existence
                if os.path.exists(local_path):
                    if transfer_manager.overwrite_all:
                        proceed = True
                    elif transfer_manager.skip_all:
                        continue
                    else:
                        filename = os.path.basename(remote_path)
                        action = OverwriteDialog(self.master, filename).result
                        
                        if action == "cancel":
                            progress_dialog.cancel_transfer()
                            break
                        elif action == "skip":
                            continue
                        elif action == "skip_all":
                            transfer_manager.skip_all = True
                            continue
                        elif action == "overwrite_all":
                            transfer_manager.overwrite_all = True
                            proceed = True
                        elif action == "overwrite":
                            proceed = True
                        else:
                            continue
                else:
                    proceed = True
                
                # Create transfer task
                if proceed:
                    # Ensure local directory exists
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    
                    task = FileTransferTask(remote_path, local_path, size, is_upload=False)
                    transfer_manager.add_task(task)
            
            # Start transfer workers
            transfer_manager.start_workers()
            
        except Exception as e:
            messagebox.showerror("Error", f"Download operation failed: {str(e)}")
            logger.error(f"Download operation failed: {str(e)}", exc_info=True)

    
    def on_transfer_complete(self, progress_dialog):
        """Handle transfer completion"""
        self.master.after(500, lambda: self.finish_transfer(progress_dialog))
    
    def finish_transfer(self, progress_dialog):
        """Clean up after transfer completes"""
        try:
            if progress_dialog.winfo_exists():
                progress_dialog.destroy()
            
            # Refresh file lists
            self.load_local_files(use_cache=False)
            self.load_remote_files(use_cache=False)
            
            # Show status
            self.status_var.set("Transfer completed")
            
        except Exception as e:
            logger.error(f"Error in finish_transfer: {str(e)}")
    
    def create_directory(self):
        """Create a new directory in the active panel"""
        dialog = CreateDirDialog(self.master)
        self.master.wait_window(dialog)
        
        if dialog.result is None:
            return
        
        new_dir_name = dialog.result
        
        if self.active_panel == 'local':
            try:
                # Create local directory
                target_path = os.path.join(self.model.local_directory, new_dir_name)
                os.makedirs(target_path, exist_ok=True)
                self.load_local_files(use_cache=False)
                messagebox.showinfo("Directory Created", f"Created local directory: {target_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create local directory: {str(e)}")
        else:
            if not self.model.is_connected:
                messagebox.showwarning("Warning", "Not connected to remote device.")
                return
            
            try:
                # Create remote directory
                remote_path = os.path.join(self.model.remote_directory, new_dir_name).replace('\\', '/')
                self.model.sftp.mkdir(remote_path)
                self.load_remote_files(use_cache=False)
                messagebox.showinfo("Directory Created", f"Created remote directory: {remote_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create remote directory: {str(e)}")
    
    def refresh_both(self):
        """Refresh both file panels"""
        self.load_local_files(use_cache=False)
        if self.model.is_connected:
            self.load_remote_files(use_cache=False)
        self.update_disk_info()
        self.status_var.set("Refreshed file lists")
            
    def delete_selected(self, source=None):
        """Delete selected files/directories"""
        if not source:
            source = self.active_panel
        
        if source == 'local':
            selected_items = self.local_tree.selection()
            if not selected_items:
                return
            
            # Confirm deletion
            if not messagebox.askyesno(
                "Confirm Delete",
                "Are you sure you want to delete the selected local items?"
            ):
                return
            
            # Process each selected item
            for item in selected_items:
                values = self.local_tree.item(item)['values']
                if values[0] == '..':
                    continue
                
                if 'file' in self.local_tree.item(item)['tags']:
                    # Delete file
                    # values[0] already contains the full filename with extension
                    filename = str(values[0])
                    
                    try:
                        full_path = os.path.join(self.model.local_directory, filename)
                        os.remove(full_path)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete file {filename}: {str(e)}")
                else:
                    # Delete directory
                    dir_name = str(values[0])
                    full_path = os.path.join(self.model.local_directory, dir_name)
                    
                    # Check if directory is empty
                    if os.path.exists(full_path) and os.listdir(full_path):
                        if not messagebox.askyesno(
                            "Confirm Delete",
                            f"The directory '{dir_name}' is not empty.\nDelete all contents?"
                        ):
                            continue
                    
                    try:
                        # Delete recursively
                        shutil.rmtree(full_path)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete directory {dir_name}: {str(e)}")
            
            # Refresh list
            self.load_local_files(use_cache=False)
            
        elif source == 'remote':
            if not self.model.is_connected:
                messagebox.showwarning("Warning", "Not connected to remote device.")
                return
            
            selected_items = self.remote_tree.selection()
            if not selected_items:
                return
            
            # Confirm deletion
            if not messagebox.askyesno(
                "Confirm Delete",
                "Are you sure you want to delete the selected remote items?"
            ):
                return
            
            # Process each selected item
            for item in selected_items:
                values = self.remote_tree.item(item)['values']
                if values[0] == '..':
                    continue
                
                if 'file' in self.remote_tree.item(item)['tags']:
                    # Delete file
                    # values[0] already contains the full filename with extension
                    filename = str(values[0])
                    
                    try:
                        full_path = os.path.join(self.model.remote_directory, filename).replace('\\', '/')
                        self.model.sftp.remove(full_path)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete file {filename}: {str(e)}")
                else:
                    # Delete directory
                    dir_name = str(values[0])
                    full_path = os.path.join(self.model.remote_directory, dir_name).replace('\\', '/')
                    
                    try:
                        # Check if directory is empty
                        dir_items = self.model.sftp.listdir(full_path)
                        if dir_items:
                            if not messagebox.askyesno(
                                "Confirm Delete",
                                f"The directory '{dir_name}' is not empty.\nDelete all contents (recursively)?"
                            ):
                                continue
                            
                            # Delete recursively
                            self.model.delete_remote_item(full_path, recursive=True)
                        else:
                            self.model.sftp.rmdir(full_path)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to delete directory {dir_name}: {str(e)}")
            
            # Refresh list
            self.load_remote_files(use_cache=False)
    
    def search_files(self):
        """Open file search dialog"""
        dialog = FileSearchDialog(
            self.master,
            self.model,
            is_remote=(self.active_panel == 'remote' and self.model.is_connected)
        )
        
        # Wait for dialog result non-modally
        self.master.wait_visibility(dialog)
        
        # Set callback for when result is returned
        def on_search_complete():
            if dialog.winfo_exists():
                if dialog.result:
                    result_path = dialog.result
                    
                    # Handle navigation to result
                    if self.active_panel == 'remote' and self.model.is_connected:
                        # Get directory part of path
                        dir_path = os.path.dirname(result_path)
                        self.model.remote_directory = normalize_path(dir_path, is_remote=True)
                        self.remote_path_var.set(self.model.remote_directory)
                        self.load_remote_files()
                        
                        # Find and select the file
                        basename = os.path.basename(result_path)
                        for item_id in self.remote_tree.get_children():
                            values = self.remote_tree.item(item_id)['values']
                            if values[0] + values[1] == basename:
                                self.remote_tree.selection_set(item_id)
                                self.remote_tree.see(item_id)
                                self.remote_tree.focus(item_id)
                                break
                    else:
                        # Get directory part of path
                        dir_path = os.path.dirname(result_path)
                        self.model.local_directory = normalize_path(dir_path)
                        self.local_path_var.set(self.model.local_directory)
                        self.load_local_files()
                        
                        # Find and select the file
                        basename = os.path.basename(result_path)
                        for item_id in self.local_tree.get_children():
                            values = self.local_tree.item(item_id)['values']
                            if values[0] + values[1] == basename:
                                self.local_tree.selection_set(item_id)
                                self.local_tree.see(item_id)
                                self.local_tree.focus(item_id)
                                break
            else:
                # Dialog closed, cancel polling
                return
            
            # Continue polling until dialog is closed
            self.master.after(100, on_search_complete)
        
        # Start polling
        self.master.after(100, on_search_complete)
    
    def compare_directories(self):
        """Compare local and remote directories"""
        if not self.model.is_connected:
            messagebox.showwarning("Warning", "Not connected to remote device.")
            return
        
        try:
            # Get file lists
            local_files = self.model.get_local_files(use_cache=False)
            remote_files = self.model.get_remote_files(use_cache=False)
            
            # Build dictionaries for comparison
            local_dict = {f.name: f for f in local_files if f.name != '..'}
            remote_dict = {f.name: f for f in remote_files if f.name != '..'}
            
            # Find differences
            only_local = [name for name in local_dict if name not in remote_dict]
            only_remote = [name for name in remote_dict if name not in local_dict]
            
            # Files in both but may differ
            in_both = [name for name in local_dict if name in remote_dict]
            different_size = [
                name for name in in_both
                if not local_dict[name].is_dir and not remote_dict[name].is_dir
                and local_dict[name].size != remote_dict[name].size
            ]
            
            # Prepare report
            report = [
                f"Directory Comparison Report",
                f"Local: {self.model.local_directory}",
                f"Remote: {self.model.remote_directory}",
                f"\n{len(only_local)} files/folders only in local directory:",
            ]
            
            for name in sorted(only_local):
                file_type = "Directory" if local_dict[name].is_dir else "File"
                report.append(f"- {file_type}: {name}")
            
            report.append(f"\n{len(only_remote)} files/folders only in remote directory:")
            for name in sorted(only_remote):
                file_type = "Directory" if remote_dict[name].is_dir else "File"
                report.append(f"- {file_type}: {name}")
            
            report.append(f"\n{len(different_size)} files with different sizes:")
            for name in sorted(different_size):
                report.append(
                    f"- {name}: Local {format_size(local_dict[name].size)} vs "
                    f"Remote {format_size(remote_dict[name].size)}"
                )
            
            # Show report
            self._show_text_report("\n".join(report), "Directory Comparison")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compare directories: {str(e)}")
    
    def sync_directories(self):
        """Synchronize directories between local and remote"""
        if not self.model.is_connected:
            messagebox.showwarning("Warning", "Not connected to remote device.")
            return
        
        # Show sync options dialog
        sync_direction = messagebox.askyesnocancel(
            "Synchronize Directories",
            "Choose synchronization direction:\n\n"
            "Yes = Upload (Local → Remote)\n"
            "No = Download (Remote → Local)\n"
            "Cancel = Abort operation",
            icon=messagebox.QUESTION
        )
        
        if sync_direction is None:
            return
        
        try:
            # Get file lists
            local_files = self.model.get_local_files(use_cache=False)
            remote_files = self.model.get_remote_files(use_cache=False)
            
            # Build dictionaries for comparison
            local_dict = {f.name: f for f in local_files if f.name != '..'}
            remote_dict = {f.name: f for f in remote_files if f.name != '..'}
            
            # Determine files to transfer
            files_to_transfer = []
            
            if sync_direction:  # Upload (Local → Remote)
                # Files only in local directory
                for name, file_item in local_dict.items():
                    if name not in remote_dict:
                        if not file_item.is_dir:
                            local_path = os.path.join(self.model.local_directory, name)
                            remote_path = os.path.join(self.model.remote_directory, name).replace('\\', '/')
                            files_to_transfer.append((local_path, remote_path, file_item.size, True))
                
                # Files in both but with different sizes
                for name, file_item in local_dict.items():
                    if name in remote_dict:
                        if not file_item.is_dir and not remote_dict[name].is_dir:
                            if file_item.size != remote_dict[name].size:
                                local_path = os.path.join(self.model.local_directory, name)
                                remote_path = os.path.join(self.model.remote_directory, name).replace('\\', '/')
                                files_to_transfer.append((local_path, remote_path, file_item.size, True))
            else:  # Download (Remote → Local)
                # Files only in remote directory
                for name, file_item in remote_dict.items():
                    if name not in local_dict:
                        if not file_item.is_dir:
                            remote_path = os.path.join(self.model.remote_directory, name).replace('\\', '/')
                            local_path = os.path.join(self.model.local_directory, name)
                            files_to_transfer.append((remote_path, local_path, file_item.size, False))
                
                # Files in both but with different sizes
                for name, file_item in remote_dict.items():
                    if name in local_dict:
                        if not file_item.is_dir and not local_dict[name].is_dir:
                            if file_item.size != local_dict[name].size:
                                remote_path = os.path.join(self.model.remote_directory, name).replace('\\', '/')
                                local_path = os.path.join(self.model.local_directory, name)
                                files_to_transfer.append((remote_path, local_path, file_item.size, False))
            
            # Check if any files to transfer
            if not files_to_transfer:
                messagebox.showinfo("Synchronize", "Directories are already synchronized.")
                return
            
            # Confirm transfer
            if not messagebox.askyesno(
                "Confirm Synchronize",
                f"Ready to synchronize {len(files_to_transfer)} files.\n\n"
                f"Direction: {'Local → Remote' if sync_direction else 'Remote → Local'}\n\n"
                "Continue?"
            ):
                return
            
            # Calculate total size
            total_size = sum(size for _, _, size, _ in files_to_transfer)
            
            # Show progress dialog
            progress_dialog = ProgressDialog(self.master, total_size, len(files_to_transfer))
            
            # Configure transfer manager
            transfer_manager = self.model.transfer_manager
            transfer_manager.overwrite_all = True  # Always overwrite during sync
            transfer_manager.skip_all = False
            
            # Clear previous callbacks
            transfer_manager.callbacks = {
                'progress': [],
                'file_complete': [],
                'all_complete': [],
                'error': []
            }
            
            # Add callbacks
            transfer_manager.add_callback('progress', lambda task: progress_dialog.update_file_progress(task))
            transfer_manager.add_callback('file_complete', lambda task: progress_dialog.file_completed(task))
            transfer_manager.add_callback('all_complete', lambda: self.on_transfer_complete(progress_dialog))
            
            # Add transfer tasks
            for src_path, dst_path, size, is_upload in files_to_transfer:
                # Create directories if needed
                if is_upload:
                    remote_dir = os.path.dirname(dst_path)
                    try:
                        self.model.sftp.chdir(remote_dir)
                    except IOError:
                        # Create remote directory structure
                        self.model._make_remote_dirs(remote_dir)
                else:
                    local_dir = os.path.dirname(dst_path)
                    os.makedirs(local_dir, exist_ok=True)
                
                # Create task
                task = FileTransferTask(src_path, dst_path, size, is_upload=is_upload)
                transfer_manager.add_task(task)
            
            # Start transfer
            transfer_manager.start_workers()
            
        except Exception as e:
            messagebox.showerror("Error", f"Synchronization failed: {str(e)}")
            logger.error(f"Synchronization failed: {str(e)}", exc_info=True)
    
    def copy_selected_path(self):
        """Copy the path of selected item to clipboard"""
        if self.active_panel == 'local':
            tree = self.local_tree
            base_path = self.model.local_directory
        else:
            tree = self.remote_tree
            base_path = self.model.remote_directory
        
        selected = tree.selection()
        if not selected:
            return
        
        item = selected[0]
        values = tree.item(item)['values']
        if not values or values[0] == '..':
            # Copy current directory path
            self.master.clipboard_clear()
            self.master.clipboard_append(base_path)
            self.status_var.set(f"Copied path: {base_path}")
            return
        
        # Build path
        filename = str(values[0]) + str(values[1])
        full_path = os.path.join(base_path, filename)
        if self.active_panel == 'remote':
            full_path = full_path.replace('\\', '/')
        
        # Copy to clipboard
        self.master.clipboard_clear()
        self.master.clipboard_append(full_path)
        self.status_var.set(f"Copied path: {full_path}")
    
    def _show_text_report(self, text, title):
        """Show a text report in a dialog"""
        dialog = tk.Toplevel(self.master)
        dialog.title(title)
        dialog.transient(self.master)
        dialog.grab_set()
        
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Text widget with scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, width=80, height=25)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=scrollbar.set)
        
        # Insert report text
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack(pady=10)
        
        # Position dialog
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = self.master.winfo_rootx() + (self.master.winfo_width() // 2) - (width // 2)
        y = self.master.winfo_rooty() + (self.master.winfo_height() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About Universal File Transfer",
            "Universal File Transfer 2.0\n\n"
            "A tool for transferring files between local and remote systems.\n\n"
            "Features:\n"
            "- Secure file transfers via SFTP\n"
            "- Directory synchronization\n"
            "- Multi-threaded transfers\n"
            "- Device management\n\n"
            "Enhanced with performance optimizations and security improvements."
        )
    
    def show_shortcuts(self):
        """Show keyboard shortcuts dialog"""
        shortcuts = [
            ("Tab", "Switch between local and remote panels"),
            ("F5 or F2", "Refresh file listings"),
            ("F3", "Search files"),
            ("F6", "Upload selected files"),
            ("F7", "Download selected files"),
            ("Delete", "Delete selected files"),
            ("Enter", "Open directory / Navigate"),
            ("Ctrl+N", "Create new directory"),
            ("Ctrl+C", "Copy selected path to clipboard"),
            ("Ctrl+Q", "Exit application")
        ]
        
        # Build text
        text = "Keyboard Shortcuts:\n\n"
        for key, desc in shortcuts:
            text += f"{key.ljust(10)} - {desc}\n"
        
        messagebox.showinfo("Keyboard Shortcuts", text)
    
    def on_closing(self):
        """Handle application closing"""
        # Save last local directory
        Config.save_last_local_directory(self.model.local_directory)
        
        # Disconnect from remote if connected
        if self.model.is_connected:
            self.model.disconnect()
        
        # Close application
        self.master.destroy()


# Utility functions
def normalize_path(path, is_remote=False):
    """Normalize a file path"""
    normalized = os.path.normpath(str(path)).replace('\\', '/')
    if is_remote and normalized != '/' and not normalized.endswith('/'):
        normalized += '/'
    return normalized

def format_size(size):
    """Format file size with appropriate units"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def format_time(seconds):
    """Format time in seconds to readable form"""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def walk_remote_dir(sftp, remote_dir):
    """Generator to walk remote directory structure"""
    dirs = []
    files = []
    
    try:
        for entry in sftp.listdir_attr(remote_dir):
            if stat.S_ISDIR(entry.st_mode):
                dirs.append(entry.filename)
            else:
                files.append(entry.filename)
    except Exception as e:
        logger.error(f"Error listing {remote_dir}: {str(e)}")
    
    yield (remote_dir, dirs, files)
    
    for d in dirs:
        new_dir = os.path.join(remote_dir, d).replace('\\', '/')
        yield from walk_remote_dir(sftp, new_dir)


# Main entry point
if __name__ == "__main__":
    # Set up nicer looking theme if available
    # try:
    #     from ttkthemes import ThemedTk
    #     root = ThemedTk(theme="arc")
    # except ImportError:
    root = tk.Tk() # Temporarily force the default Tkinter theme
    root.iconbitmap(resource_path("rptransfer.ico"))
    logger.info("Using default Tk theme for testing dialog size") # Modified logging message
    
    # Configure application
    root.title("Universal File Transfer") # RPTransfer_1.2.py
    
    # Set app icon if available
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico") # RPTransfer_1.2.py
        if os.path.exists(icon_path): # RPTransfer_1.2.py
            root.iconbitmap(icon_path) # RPTransfer_1.2.py
    except Exception: # RPTransfer_1.2.py
        pass # RPTransfer_1.2.py
    
    # Create and start application
    app = FileTransfer(root) # RPTransfer_1.2.py
    root.protocol("WM_DELETE_WINDOW", app.on_closing) # RPTransfer_1.2.py
    
    # Center window on screen
    root.update_idletasks() # RPTransfer_1.2.py
    width = root.winfo_width() # RPTransfer_1.2.py
    height = root.winfo_height() # RPTransfer_1.2.py
    x = (root.winfo_screenwidth() // 2) - (width // 2) # RPTransfer_1.2.py
    y = (root.winfo_screenheight() // 2) - (height // 2) # RPTransfer_1.2.py
    root.geometry(f"{width}x{height}+{x}+{y}") # RPTransfer_1.2.py
    
    # Start main loop
    root.mainloop() # RPTransfer_1.2.py