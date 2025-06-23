# ConnStruct - Structured Connection Manager
SSH and RDP - Organise. Connect. Control.
**Version:** 1.4.1
**Author:** Jake Morgan ([https://dba.wales](https://dba.wales))

## Overview

ConnStruct is a desktop application designed to help you manage and organize your remote server connections, primarily focusing on SSH and RDP sessions.  It provides a clean, tabbed interface with a tree-style explorer to keep your connections structured and easily accessible.

The goal of ConnStruct is to provide a seamless connection experience by securely storing your credentials (including passwords and SSH key passphrases) and pre-filling them when launching sessions, minimising the need for repeated manual entry.

![image](https://github.com/user-attachments/assets/d301e77e-9c39-4c33-a40b-3ec62fff5b8f)

## Features

*   **Unified Connection Management:** Manage both SSH and RDP connections from a single application.
*   **Tabbed Interface:** Open multiple remote SSH sessions in separate tabs for easy switching (a tabbed interface hasn't yet been implemented for RDP sessions).
*   **Structured Explorer:** Organise connections into user-defined folders within a tree view.
*   **Secure Credential Storage:**
    *   Uses a **master password** to encrypt all stored connection passwords and SSH key passphrases.
    *   Connection details are stored locally in encrypted JSON files (`connections.json`, `settings.json`).
*   **SSH Support:**
    *   Password authentication.
    *   Private key authentication (supports keys with or without passphrases).
    *   Customisable port.
    *   Leverages a bundled instance of [webssh](https://github.com/huashengdun/webssh) for the in-app terminal experience, launching a dedicated `webssh` process for each SSH tab.
*   **RDP Support:**
    *   Launches the system's native Remote Desktop Client (`mstsc.exe` on Windows, attempts `open rdp://` on macOS, or `xfreerdp`/`rdesktop` on Linux).
    *   Customisable port.
    *   Option to set preferred display resolution for RDP sessions.
*   **Favorites:** Quickly access your most used connections via a dedicated "Favorites" section.
*   **Search Functionality:** Filter and find connections by name, hostname, notes, or port.
*   **Customisable Connection Icons:** Assign custom colours to your SSH and RDP connection icons for better visual organisation.
*   **Drag and Drop:** Easily organise connections by dragging them into folders in the explorer.
*   **Dark/Light Theme Switcher:** Choose your preferred UI theme.

## How It Works (SSH Sessions)

For SSH sessions, ConnStruct launches a local, dedicated instance of the `webssh` application (from the `huashengdun/webssh` repository) for each SSH tab. This `webssh` instance runs on a dynamically assigned free port on your local machine.

ConnStruct then loads the `webssh` page in an embedded browser view within the tab. Using JavaScript injection, ConnStruct programmatically populates the connection details (hostname, SSH port, username, password, or private key content and passphrase) into the `webssh` interface and initiates the connection. This provides a seamless login experience directly into the terminal.

## Setup and Installation

### Prerequisites

*   **Python 3.8+**
*   **Git** (for cloning the `webssh` repository during setup)
*   **Pip** (Python package installer)
*   (For RDP on Linux) An RDP client like `xfreerdp` or `rdesktop` installed and in your PATH.

### Local Setup (for Development or Running from Source)

1.  **Clone this Repository (ConnStruct):**
    ```bash
    git clone https://github.com/jakemorgangit/ConnStruct
    cd ConnStruct 
    ```

2.  **Set up `webssh` Dependency:**
    ConnStruct relies on the `webssh` project. You need to clone it into the root of the `ConnStruct` project directory:
    ```bash
    git clone https://github.com/huashengdun/webssh.git
    ```
    This will create a `webssh` subdirectory inside your `ConnStruct` project.

3.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    ```
    Activate it:
    *   Windows: `venv\Scripts\activate`
    *   macOS/Linux: `source venv/bin/activate`

4.  **Install Python Dependencies:**
    *   Install ConnStruct's direct dependencies:
        ```bash
        pip install PyQt5 PyQtWebEngine cryptography qdarkstyle
        ```
    *   Install `webssh`'s dependencies:
        ```bash
        cd webssh
        pip install -r requirements.txt
        cd ..
        ```

5.  **Run ConnStruct:**
    ```bash
    python ConnStruct.py
    ```

## Building the Executable (Windows)

You can package `ConnStruct` into a single Windows executable (`.exe`) using PyInstaller.

1.  **Ensure all dependencies are installed** in your virtual environment as described in the "Local Setup" section.
2.  **Install PyInstaller:**
    ```bash
    pip install pyinstaller
    ```
3.  **Prepare Your Icon (Optional but Recommended):**
    *   Have an icon file (e.g., `folder_shell_icon.ico`) in the root of your `ConnStruct` project directory.
4.  **Build using PyInstaller:**
    Navigate to your `ConnStruct` project root directory in the terminal (with the virtual environment activated) and run the following command:

    ```bash
    pyinstaller --onefile --name ConnStruct --windowed --icon="folder_shell_icon.ico" --add-data "webssh:webssh" --add-data "folder_shell_icon.ico:." --hidden-import "PyQt5.QtWebEngineWidgets" --hidden-import "paramiko" --hidden-import "tornado" --hidden-import "bcrypt" --hidden-import "pynacl" ConnStruct.py
    ```

    **Explanation of PyInstaller flags:**
    *   `--onefile`: Creates a single executable file.
    *   `--name ConnStruct`: Sets the name of the output executable.
    *   `--windowed`: Creates a GUI application (no console window).
    *   `--icon="folder_shell_icon.ico"`: Specifies your application icon.
    *   `--add-data "webssh:webssh"`: Bundles the entire `webssh` sub-directory. The `webssh` folder (source) will be available as a `webssh` folder (destination) at the root of the bundled application's temporary extraction path.
    *   `--add-data "folder_shell_icon.ico:."`: Bundles the icon file to the root of the extraction path.
    *   `--hidden-import "PyQt5.QtWebEngineWidgets"`: Ensures this necessary Qt module is included.
    *   `--hidden-import "paramiko"`: Includes the Paramiko library (a dependency of `webssh`).
    *   `--hidden-import "tornado"`: Includes the Tornado library (a dependency of `webssh`).
    *   `--hidden-import "bcrypt"` and `--hidden-import "pynacl"`: These are often required by `paramiko` and might be missed by PyInstaller's auto-detection. Including them can prevent runtime errors.
    *   `ConnStruct.py`: Your main application script.

5.  The executable will be found in the `dist` folder (e.g., `dist/ConnStruct.exe`).

    **Note on Antivirus:** Antivirus software can sometimes interfere with PyInstaller or flag the created executables (especially one-file executables). You might need to temporarily disable your AV during the build or add an exclusion for your project/dist folder.

## Usage

1.  **First Run:** You will be prompted to set a master password. This password encrypts all your stored connection details. **Choose a strong password and remember it!**
2.  **Adding Connections:**
    *   Click the "Add" button to create a new SSH or RDP connection.
    *   Click the "Folder" button to create a new folder for organizing connections.
3.  **Editing Connections:** Select a connection in the tree to edit its properties in the right-hand pane.
    *   **SSH:** Configure hostname, port, username, password. Optionally, provide a path to an SSH private key and its passphrase (for passphrase-protected keys, ensure your SSH agent is configured to handle them for seamless login).
    *   **RDP:** Configure hostname, port, username, password, and desired display resolution.
    *   **Icon Colour:** Customise the icon color for SSH and RDP connections.
4.  **Launching Sessions:** Double-click a connection in the tree, or right-click and select "Launch".
5.  **Favorites:** Right-click a connection and select "Add to Favorites" or "Remove from Favorites".
6.  **Search:** Use the search box at the top of the connection list to filter connections.
7.  **Themes:** Change between light and dark themes via the "View" -> "Theme" menu.


## Future Enhancements

*   Import/Export of connection data.
*   More advanced `webssh` process management and error reporting.
*   Support for other protocols.
*   Direct integration with system SSH agent for adding keys.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request on the GitHub repository.

## License

MIT
