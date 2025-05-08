# ✨ Hyper Cleaner ✨

Built by **John Carvalho**

A comprehensive command-line utility for Windows, built with **Python**, designed to help clean, optimize, and maintain your system. It offers a range of tools from disk cleaning and memory optimization to system file repairs and security scans, all accessible through an easy-to-use console interface.

---

## 🔧 Features

- ✅ **Interactive Console Menu (`display_menu`, `main`):**
    - **Details:** The script utilizes the `rich` Python library to create a visually appealing and interactive menu in the command-line interface. The `display_menu` function constructs and prints this menu, listing all available optimization and maintenance tasks with corresponding numbers. The `main` function's loop captures user input and calls the appropriate function based on the numerical selection. This provides a more engaging and user-friendly experience compared to a plain text-based menu.

- ✅ **System Cleaning:**
    - **Cache & Temporary Files (`clean_disk_cache`):**
        - **Details:** This function performs a multi-step cleaning process:
            1.  **Disk Cleanup Utility (`cleanmgr.exe`):** Attempts to launch the built-in Windows Disk Cleanup tool by executing `cleanmgr.exe /sagerun:1`. The effectiveness of this step depends on the user having previously configured cleanup settings using `cleanmgr.exe /sageset:1` (as an administrator). The script itself doesn't select what `cleanmgr.exe` deletes but triggers its automated run based on prior user configuration.
            2.  **Manual Temporary Folder Cleaning:** Programmatically identifies the user's temporary folder (from the `%TEMP%` environment variable) and the system's temporary folder (`C:\Windows\Temp`). It then iterates through all files and subdirectories within these locations, attempting to delete them using `os.unlink()` for files/symlinks and `shutil.rmtree()` for directories. It includes basic error handling to skip files that are in use or cannot be deleted due to permissions, logging these occurrences.
            3.  **DISM Component Store Cleanup (`DISM.exe`):** Executes the command `DISM.exe /Online /Cleanup-Image /StartComponentCleanup`. This Windows utility cleans up the WinSxS folder (Component Store) by removing outdated and superseded system component versions, which can free up considerable disk space. The script captures and logs the output of this command.
    - **Event Log Clearing (`clear_event_logs`):**
        - **Details:** Employs a PowerShell command to clear various Windows event logs. The command `Get-WinEvent -ListLog * | Where-Object {$_.IsEnabled -and $_.RecordCount -gt 0 -and $_.LogType -eq 'Operational' -and ($_.LogName -like 'Application' -or $_.LogName -like 'System' -or $_.LogName -like 'Security' -or $_.LogName -like 'Setup' -or $_.LogName -match 'Microsoft-Windows-.*/Operational')} | ForEach-Object { Clear-EventLog -LogName $_.LogName -ErrorAction SilentlyContinue }` lists enabled operational logs (specifically Application, System, Security, Setup, and key Microsoft-Windows operational logs) that have records and then attempts to clear each one. The user is warned before this action as it can make troubleshooting recent system issues more difficult.
    - **DNS Cache Flush (`flush_dns_cache`):**
        - **Details:** Executes the command `ipconfig /flushdns`. This command clears the local DNS resolver cache on the Windows system. The DNS cache stores the IP addresses of recently visited websites. Flushing it can resolve issues related to outdated DNS records, website access problems, or certain network connectivity errors.

- ✅ **Performance Optimization:**
    - **Memory Optimizer (`optimize_memory`):**
        - **Details:** This function uses the `psutil` library to identify and offer termination for processes consuming significant memory:
            1.  It iterates through all running processes using `psutil.process_iter()`, gathering information like PID, name, memory usage (RSS - Resident Set Size), username, and executable path.
            2.  It filters out critical system processes (e.g., `csrss.exe`, `wininit.exe`), processes running under system accounts (`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`), the Python script's own process, and non-essential Windows processes that are generally safe to leave running unless specifically problematic. It also avoids processes located in `C:\Windows` unless they are on a small allowlist (like `explorer.exe`).
            3.  Processes consuming more than a predefined threshold (e.g., 50MB RAM) are listed in a table for the user.
            4.  The user can select one or more processes by number to terminate. The script first attempts a graceful termination (`process_obj.terminate()`) and waits briefly. If the process doesn't exit, it forces termination (`process_obj.kill()`).
    - **Startup Optimizer (`optimize_startup`):**
        - **Details:** Scans several standard Windows Registry locations known to contain entries for programs that launch at startup. These include:
            - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
            - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
            - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
            - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
            - And their `Wow6432Node` equivalents for 32-bit applications on 64-bit systems.
            It uses the `winreg` module to read these keys, lists the program names and their associated commands/paths, and allows the user to select entries for removal. Disabling an item involves deleting the specific registry value using `winreg.DeleteValue()`.
    - **Visual Effects Adjustment (`optimize_visuals`):**
        - **Details:** Modifies a single Registry value to set Windows visual effects to the "Best Performance" preset. It accesses `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects` and sets the `VisualFXSetting` (REG_DWORD) value to `2`. This instructs Windows to disable many non-essential graphical effects like animations, shadows, and smooth font edges, which can improve UI responsiveness on less powerful systems.
    - **MenuShowDelay Tweak (`set_menu_show_delay`):**
        - **Details:** Adjusts the `MenuShowDelay` value in the Registry key `HKEY_CURRENT_USER\Control Panel\Desktop`. This string value (REG_SZ) controls the time (in milliseconds) Windows waits before displaying a cascaded menu when the mouse hovers over its parent item. The script sets this to a low value (e.g., "20", default is typically "400") to make menus appear almost instantly.
    - **Power Plan Optimization (`set_power_plan`):**
        - **Details:** Interacts with `powercfg.exe` to manage system power plans:
            1.  **Enable Ultimate Performance:** Attempts to make the "Ultimate Performance" plan available by running `powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61`. This command reveals the GUID if the plan is hidden or confirms its existence.
            2.  **List Plans:** Executes `powercfg /list` to get a list of all available power plans and their GUIDs.
            3.  **Select Plan:** It prioritizes activating the "Ultimate Performance" plan using its known or discovered GUID. If "Ultimate Performance" is not available, it attempts to activate the "High Performance" plan (`8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c`). It checks for both English and Portuguese names of these plans.
            4.  **Activate Plan:** Uses `powercfg /setactive <GUID_of_chosen_plan>` to make the selected optimized plan the current one.
    - **Hibernation Toggle (`enable_hibernation`, `disable_hibernation` via `toggle_hibernation_option`):**
        - **Details:** Uses `powercfg.exe /hibernate on` to enable hibernation or `powercfg.exe /hibernate off` to disable it.
            - Disabling hibernation removes the `hiberfil.sys` file (located at `C:\hiberfil.sys`), which is used to store the contents of RAM during hibernation. This frees up disk space equivalent to a significant portion of your installed RAM but also disables the Fast Startup feature in Windows.
            - Enabling hibernation recreates `hiberfil.sys` and re-enables the hibernation and Fast Startup capabilities.

- ✅ **System Maintenance & Repair:**
    - **System Restore Point (`create_restore_point`):**
        - **Details:** Leverages PowerShell's `Checkpoint-Computer` cmdlet. It executes `Checkpoint-Computer -Description "HyperCleaner_RP_{timestamp}" -RestorePointType MODIFY_SETTINGS`. This creates a snapshot of critical system files and settings, allowing the user to revert the system to this state if subsequent changes made by Hyper Cleaner or other software cause instability.
    - **System File Checker (SFC) (`run_system_maintenance` - part 1):**
        - **Details:** Executes the command `sfc /scannow`. This built-in Windows utility scans all protected system files, verifies their versions, and replaces corrupted or missing files with correct versions from the system's cache or the Windows installation source. The script displays the output to the user.
    - **DISM Image Repair (`run_system_maintenance` - part 2):**
        - **Details:** Executes `DISM.exe /Online /Cleanup-Image /RestoreHealth`. The Deployment Image Servicing and Management (DISM) tool is used here to scan the Windows component store for corruption and automatically perform repairs. It can use Windows Update to download fresh copies of corrupted files if necessary. This is often a more robust repair mechanism than SFC for certain types of system image corruption. The script displays the output.
    - **Network Reset (`reset_network_settings`):**
        - **Details:** Performs two key network reset operations using `netsh.exe`:
            1.  **Winsock Reset:** Executes `netsh winsock reset`. This command resets the Winsock Catalog to its default (clean) state. It can resolve network connectivity issues caused by corrupted Layered Service Providers (LSPs) or other Winsock-related problems.
            2.  **TCP/IP Reset:** Executes `netsh int ip reset`. This command rewrites essential TCP/IP registry keys, effectively resetting the TCP/IP stack to its original configuration. It can fix problems related to IP addressing or other TCP/IP protocol issues.
            The user is warned that a system restart is required for these changes to fully take effect.

- ✅ **Security:**
    - **Windows Defender Scans (`run_defender_quick_scan`, `run_defender_full_scan` via `run_defender_scan_action`):**
        - **Details:**
            1.  **Find MpCmdRun.exe (`get_defender_path`):** The script first attempts to locate `MpCmdRun.exe`, the command-line interface for Windows Defender. It checks common installation paths, including versioned platform directories under `C:\ProgramData\Microsoft\Windows Defender\Platform`.
            2.  **Update Signatures:** Before scanning, it runs `MpCmdRun.exe -SignatureUpdate` to ensure Windows Defender has the latest virus and spyware definitions.
            3.  **Initiate Scan:** It then executes `MpCmdRun.exe -Scan -ScanType 1` for a Quick Scan (checks common locations for malware) or `MpCmdRun.exe -Scan -ScanType 2` for a Full Scan (scans all files and running programs, which is more time-consuming). The scan is started in the background, and the script informs the user to monitor progress via Windows Defender notifications.

- ✅ **Administrator Privileges Check (`is_admin`):**
    - **Details:** Uses the `ctypes` library to interface with the Windows API. Specifically, it calls `ctypes.windll.shell32.IsUserAnAdmin()`. This function returns a non-zero integer if the script is running with administrator privileges, and `0` otherwise. The script checks this at startup and exits with a message if not run as admin, as most of its functions require elevated permissions to modify system settings or access protected resources.

- ✅ **Logging (`setup_logging`, and used throughout other functions):**
    - **Details:** Implements logging using Python's standard `logging` module. The `setup_logging` function configures a logger to write messages to a file named `hyper_cleaner.log`. Log messages include a timestamp, log level (e.g., INFO, WARNING, ERROR), the name of the function where the log event occurred, and the specific message. This provides a persistent record of the script's operations and any errors encountered, which is useful for troubleshooting.

---

## 🚀 Tech Stack

- **Core:** Python 3.x
- **Command-Line Interface:** `rich` (for styled tables, panels, and print output)
- **System Interaction:**
    - `psutil` (for process information and memory usage)
    - `winreg` (for interacting with the Windows Registry)
    - `ctypes` (for checking administrator privileges)
    - `subprocess` (for executing external commands like `powercfg`, `DISM`, `sfc`, `ipconfig`, `MpCmdRun.exe`, `netsh`, PowerShell)
- **File System & OS:** `os`, `shutil`
- **Logging:** Python `logging` module

---

## ⚙️ Setup and Usage

### 🔹 Step 1: Prerequisites

- Ensure you have **Python 3** installed on your system (Python 3.7+ recommended). You can check by running `python --version` or `python3 --version`.
- You'll need `pip` (Python's package installer), which usually comes with Python.
- This script is designed for **Windows Operating Systems** only.

### 🔹 Step 2: Download the App

- Download the Python script (e.g., `hyper_cleaner.py`) to a directory on your computer.

### 🔹 Step 3: Install Dependencies

1.  Navigate to the directory where you saved the file using your terminal or command prompt (CMD or PowerShell).
    ```bash
    cd path\to\your\script\directory
    ```
2.  Install the required Python libraries:
    ```bash
    pip install rich psutil
    ```
    * `rich` is needed for the enhanced console user interface.
    * `psutil` is needed for process management and system information.

### 🔹 Step 4: Run the Script

- Execute the program from your terminal **as an Administrator**. Right-click on CMD or PowerShell and select "Run as administrator", then navigate to the script directory and run:
    ```bash
    python hyper_cleaner.py
    ```
- If not run as administrator, the script will notify you and exit.

### 🔹 Step 5: Interact with the Console

1.  Upon successful launch, you will see the main menu:
    ```
    +--------------------------------------------------------------------------------------------------+
    | Main Menu                                                                                        |
    |--------------------------------------------------------------------------------------------------|
    | 🚀 Hyper Cleaner By John Carvalho 🚀                                                             |
    | Choose an option:                                                                                |
    +--------------------------------------------------------------------------------------------------+
    [1]   🛡️ Create Restore Point                      Creates a system backup before major changes.
    [2]   🧹 Clean Caches and Temporary Files           Frees up space and removes system junk.
    [3]   🧠 Optimize Memory (RAM Tweaker)              Closes unnecessary processes to free up RAM.
    [4]   🚀 Optimize Startup (Registry)                Manages programs that start with Windows.
    [5]   🎨 Adjust Visual Effects (Best Performance)    Reduces visual effects to speed up the interface.
    [6]   ⚡ Set Optimized Power Plan                  Changes to High or Ultimate Performance.
    [7]   🛠️ Run System Maintenance (SFC & DISM)         Checks and repairs system files.
    [8]   ⚔️ Quick Scan (Windows Defender)               Quick check for common threats.
    [9]   🔍 Full Scan (Windows Defender)                Deep scan of the entire system (time-consuming).
    [10]  🌐 Clear DNS Cache                            Resolves connection and website access issues.
    [11]  🔄 Reset Network Settings                      Restores network settings (requires restart).
    [12]  🔋 Disable Hibernation                         Frees up disk space (removes hiberfil.sys).
    [13]  🔌 Enable Hibernation                         Restores hibernation functionality.
    [14]  🗑️ Clear Windows Event Logs                    Clears main logs (use with caution).
    [15]  ⚙️ Adjust Menu Delay (MenuShowDelay)           Speeds up context menu display.
    [0]   🚪 Exit                                      Closes Hyper Cleaner.

    👉 Enter the number of the desired option:
    ```
    *(The exact appearance will be styled by the `rich` library).*
2.  At the `👉 Enter the number of the desired option:` prompt, type the number corresponding to the action you want to perform and press Enter.
3.  Follow any on-screen prompts. Some operations may require confirmation (e.g., "Are you sure? (y/N)") or will inform you if a restart is needed.
4.  After an operation is completed, you will usually be prompted to press Enter to return to the main menu.
5.  To close the application, choose option `0` (Exit).

---

## 🌐 Accessing the Service

- **Console Only:** Interaction with Hyper Cleaner is done exclusively through the command-line interface where the script is run.
- **Administrator Privileges:** Crucial for most operations, as they involve system-level changes (Registry, system files, services).

---

## 🧠 Features in Future Updates:

- 💾 **Configuration Profiles:** Allow saving and loading sets of preferred optimization settings.
- 📊 **Detailed Reporting:** Generate more comprehensive reports after operations (e.g., space saved, specific items cleaned/fixed).
- 📅 **Task Scheduling (Basic):** Integrate with Windows Task Scheduler for some routine cleanups (though complex for a CLI tool).
- 📦 **More Cleaning Targets:** Add options for cleaning browser caches, specific application caches, etc.
- 🛡️ **Advanced Registry Tools:** More granular registry cleaning or tweaking options (with extreme caution).
- 🌐 **Internationalization:** Expand language support for messages from system commands.
- ↩️ **Undo Specific Tweaks:** For some reversible changes, provide an explicit undo option beyond System Restore.

---

## 👨‍💻 Author

**John Carvalho**

If something is wrong, don't hesitate to tell me!
