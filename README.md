# RPTransfer - Universal File Transfer Application

A feature-rich SFTP file transfer client with a dual-pane GUI, built using Python and Tkinter for managing files on remote systems like Raspberry Pi and PCs.

![RPTransfer Screenshot](https://raw.githubusercontent.com/gthank/RPTransfer/main/screenshots/Dark-Theme.png)
*(Note: You would replace the placeholder URL above with an actual screenshot of your application.)*

## Key Features

* **Dual-Pane Interface**: Easily manage files with a classic local and remote panel view.
* **Secure Transfers**: Uses the Paramiko library for secure SFTP (SSH File Transfer Protocol) connections.
* **Device Management**:
    * Save, edit, and remove remote device configurations for quick connections.
    * A "Deauthorize" button allows for clearing saved credentials for a specific device.
* **Secure Credential Storage**: Uses the `keyring` library to securely store passwords in the system's native credential manager.
* **Comprehensive File Operations**:
    * Upload and download single files or entire directories recursively.
    * Create and delete files and directories on both local and remote systems.
    * Multi-threaded transfers with a detailed progress dialog showing overall and per-file progress, speed, and time remaining.
* **Advanced Tools**:
    * **Directory Comparison**: Generate a report showing differences between the local and remote directories.
    * **Directory Synchronization**: Synchronize directories in either direction (upload or download).
    * **File Search**: Search for files and folders on the local or remote system.
* **User-Friendly Experience**:
    * Sort file lists by name, extension, or date.
    * Displays local and remote disk space information.
    * Saves the last used local directory upon exit.
    * Keyboard shortcuts for common operations.

## Core Technologies

* **Python 3**
* **Tkinter** (for the GUI)
* **Paramiko** (for SFTP/SSH functionality)
* **Keyring** (for secure credential storage)

## Getting Started

### Prerequisites

You need Python 3 and the following libraries.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/RPTransfer.git](https://github.com/your-username/RPTransfer.git)
    cd RPTransfer
    ```

2.  **Install the required Python libraries:**
    ```bash
    pip install paramiko keyring
    ```
    *Note: On Linux, you may need to install a backend for `keyring`, such as `SecretStorage`. `pip install secretstorage`.*

3.  **Configuration File:**
    The application uses a `rptrans_config.json` file in the same directory to store device configurations and the last visited local path. If this file is not found on first launch, a default one will be created.

    You can pre-populate this file. It should look like this:
    ```json
    {
      "devices": {
        "KODI": {
          "type": "pi",
          "connection": "root@libreELEC",
          "directory": "/storage/videos/"
        },
        "Remote PC": {
          "type": "pc",
          "connection": "user@192.168.2.39",
          "directory": "c:/work/Pictures"
        }
      },
      "last_local_directory": "C:/path/to/your/files"
    }
    ```

### Running the Application

Execute the python script from your terminal:
```bash
python RPTransfer.py
