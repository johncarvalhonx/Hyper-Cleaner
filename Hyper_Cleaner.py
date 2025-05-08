# -*- coding: utf-8 -*-

import ctypes
import os
import subprocess
import sys
import logging
import winreg # To interact with the Windows Registry
import shutil # For directory removal operations
from datetime import datetime
import re # Regular expressions module for parsing
import time # For pauses, if necessary

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
except ImportError:
    print("Error: The 'rich' library is not installed.")
    print("Execute: pip install rich")
    sys.exit(1)

try:
    import psutil # To list processes and memory usage
except ImportError:
    print("Error: The 'psutil' library is not installed.")
    print("Execute: pip install psutil")
    sys.exit(1)

# --- Constants ---
LOG_FILENAME = "hyper_cleaner.log"
AUTHOR_NAME = "John Carvalho" # Keep as is, or you can change it
APP_TITLE = f"🚀 Hyper Cleaner v1.0 By {AUTHOR_NAME} 🚀"

# Power Plan GUIDs (Common)
GUID_ULTIMATE_PERFORMANCE = "e9a42b02-d5df-448d-aa00-03f14749eb61"
GUID_HIGH_PERFORMANCE = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
GUID_BALANCED = "381b4222-f694-41f0-9685-ff5bb260df2e"
GUID_POWER_SAVER = "a1841308-3541-4fab-bc81-f71556f20b4a"

# Registry Keys for Startup Programs
STARTUP_REG_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    # For 64-bit systems, also check Wow6432Node keys
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"), # Less common, but possible
    (winreg.HKEY_CURRENT_USER, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),# Less common
]

# Registry Keys for Visual Effects (Adjust for Best Performance)
VISUAL_EFFECTS_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
VISUAL_EFFECTS_VALUE_NAME = "VisualFXSetting"
VISUAL_EFFECTS_BEST_PERFORMANCE_VALUE = 2 # 0=Let Windows choose, 1=Best appearance, 2=Best performance, 3=Custom

# Registry for MenuShowDelay
MENU_SHOW_DELAY_KEY_PATH = r"Control Panel\Desktop"
MENU_SHOW_DELAY_VALUE_NAME = "MenuShowDelay"
MENU_SHOW_DELAY_FAST_VALUE = "20" # Fast value (default is "400")

# --- Logging Configuration ---
def setup_logging():
    """Configures logging to a file."""
    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - [%(levelname)s] - %(funcName)s - %(message)s',
            filename=LOG_FILENAME,
            filemode='a', # 'a' for append
            encoding='utf-8'
        )
    except PermissionError:
        rprint(f"[bold red]Permission error when trying to create/write to the log file: {LOG_FILENAME}[/bold red]")
        rprint("[yellow]Logs will not be saved to a file.[/yellow]")
    except Exception as e:
        rprint(f"[bold red]Unexpected error configuring logging: {e}[/bold red]")

# --- Utility Functions ---
console = Console()

def clear_console():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def press_enter_to_continue():
    """Waits for the user to press Enter."""
    rprint("\n[yellow i]Press Enter to return to the main menu...[/yellow i]")
    input()

def is_admin():
    """Checks if the script is running with administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        logging.error("Failed to check admin privileges (AttributeError). Assuming non-admin.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error when checking admin privileges: {e}")
        return False

def run_command(command, capture=False, shell_mode=False, check_ret=True, display_output=False):
    """Executes a system command and returns the result."""
    log_msg = f"Executing command: {' '.join(command) if isinstance(command, list) else command}"
    logging.info(log_msg)
    if display_output:
        rprint(f"[dim]Executing: {log_msg}[/dim]")
    try:
        result = subprocess.run(
            command,
            capture_output=capture or display_output, # Capture if display_output is True
            text=True,
            shell=shell_mode,
            check=check_ret if not display_output else False, # If display_output, we check manually
            encoding='cp850', # Common encoding for cmd/powershell in Brazil (can be changed to 'utf-8' or None for broader compatibility)
            errors='ignore'
        )
        logging.info(f"Command executed. Return code: {result.returncode}")
        if capture or display_output:
            if result.stdout: logging.debug(f"Output (stdout):\n{result.stdout}")
            if result.stderr: logging.debug(f"Output (stderr):\n{result.stderr}")

        if display_output:
            if result.stdout: rprint(f"[dim]Output:\n{result.stdout}[/dim]")
            if result.stderr: rprint(f"[dim yellow]Errors (if any):\n{result.stderr}[/dim yellow]")
            if check_ret and result.returncode != 0: # Manual check if display_output
                raise subprocess.CalledProcessError(result.returncode, command, output=result.stdout, stderr=result.stderr)
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"Error executing command: {e}. Return code: {e.returncode}"
        logging.error(error_msg)
        if capture or display_output: # Even if check_ret=True, there might be output
            if e.stdout: logging.error(f"Error output (stdout):\n{e.stdout}")
            if e.stderr: logging.error(f"Error output (stderr):\n{e.stderr}")
        rprint(f"[bold red]Error executing command:[/bold red] {e}")
        if e.stderr: rprint(f"[red]{e.stderr}[/red]")
        elif e.stdout: rprint(f"[yellow]Output (stdout):\n{e.stdout}[/yellow]")
        return e # Return the error object for external analysis if needed
    except FileNotFoundError:
        cmd_name = command[0] if isinstance(command, list) else command.split()[0]
        error_msg = f"Error: Command or executable not found: {cmd_name}"
        logging.error(error_msg)
        rprint(f"[bold red]{error_msg}[/bold red]")
        return None
    except Exception as e:
        error_msg = f"Unexpected error executing command: {e}"
        logging.error(error_msg, exc_info=True)
        rprint(f"[bold red]Unexpected error:[/bold red] {e}")
        return None

# --- Optimization Functions ---

def create_restore_point():
    """Creates a System Restore Point."""
    clear_console()
    rprint(Panel("[bold cyan]🌟 Creating System Restore Point...[/bold cyan]", title="🛡️ Security", border_style="magenta"))
    logging.info("Initiating System Restore Point creation.")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    ps_script = (
        f'try {{ Checkpoint-Computer -Description "HyperCleaner_RP_{timestamp}" -RestorePointType MODIFY_SETTINGS; Write-Host "SUCCESS" }} '
        f'catch {{ Write-Error $_.Exception.Message; exit 1 }}'
    )
    ps_command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script]

    result = run_command(ps_command, capture=True, shell_mode=False)

    if result and result.returncode == 0 and "SUCCESS" in (result.stdout or ""):
        rprint("[bold green]✅ System Restore Point created successfully![/bold green]")
        logging.info("System Restore Point created successfully.")
    elif result and result.stderr:
        # Check for both English and Portuguese messages for existing restore point
        if "another system restore point has already been created" in result.stderr.lower() or \
           "outro ponto de restauração do sistema já foi criado" in result.stderr.lower():
            rprint("[bold yellow]⚠️ Warning: A System Restore Point may have already been created recently (within the last 24h).[/bold yellow]")
            logging.warning(f"Failed to create Restore Point: Recent point already exists. PS Error: {result.stderr.strip()}")
        else:
            rprint("[bold red]❌ Failed to create System Restore Point.[/bold red]")
            logging.error(f"Failed to create Restore Point. Code: {result.returncode}, Error: {result.stderr.strip()}")
            rprint(f"[red]Error details: {result.stderr.strip()}[/red]")
    else:
        rprint("[bold red]❌ Failed to create System Restore Point (command did not execute or unknown error).[/bold red]")
        log_msg = "Failed to create Restore Point."
        if result:
            log_msg += f" Code: {result.returncode}."
            if result.stdout: log_msg += f" Output: {result.stdout.strip()}"
            if result.stderr: log_msg += f" Error: {result.stderr.strip()}"
        else:
            log_msg += " The command did not return a result."
        logging.error(log_msg)

def clean_disk_cache():
    """Executes disk cleanup, caches, and components."""
    clear_console()
    rprint(Panel("[bold cyan]🧹 Cleaning Caches and Temporary Files...[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting disk/cache cleanup.")
    tasks_done = 0
    tasks_failed = 0

    # 1. Try to run cleanmgr with sageset 1
    rprint("\n[cyan]▶️ Trying to run Disk Cleanup (cleanmgr /sagerun:1)...[/cyan]")
    rprint("[yellow]    Note: This step requires you to have configured cleanup options with 'cleanmgr /sageset:1' previously via CMD (as admin).[/yellow]")
    logging.info("Trying to run cleanmgr /sagerun:1.")
    # It's difficult to get a useful return code from cleanmgr for full automation.
    # We just start it and inform the user.
    try:
        subprocess.Popen(["cleanmgr.exe", "/sagerun:1"])
        rprint("[green]    cleanmgr command started. If configured, it will clean selected items.[/green]")
        rprint("[yellow]    Check the Disk Cleanup window if it appears to follow progress.[/yellow]")
        logging.info("cleanmgr /sagerun:1 command started (no completion check).")
        # We don't consider success/failure here as it's interactive/background
    except FileNotFoundError:
        rprint("[red]    Failed to start cleanmgr.exe (not found).[/red]")
        logging.error("Failed to start cleanmgr.exe (not found).")
        tasks_failed +=1
    except Exception as e:
        rprint(f"[red]    Error trying to start cleanmgr: {e}[/red]")
        logging.error(f"Error trying to start cleanmgr: {e}")
        tasks_failed +=1


    # 2. Clean temporary folders manually
    rprint("\n[cyan]▶️ Cleaning temporary folders (%TEMP% and C:\\Windows\\Temp)...[/cyan]")
    temp_folders_to_clean = []
    try:
        user_temp = os.environ.get('TEMP') # More robust than expandvars for TEMP
        if user_temp and os.path.isdir(user_temp):
            temp_folders_to_clean.append(user_temp)
        else:
            rprint(f"[yellow]    Warning: %TEMP% folder ({user_temp}) not found or not a directory.[/yellow]")
            logging.warning(f"%TEMP% folder ({user_temp}) not found.")
    except Exception as e:
        rprint(f"[red]    Error accessing %TEMP%: {e}[/red]")
        logging.error(f"Error accessing %TEMP%: {e}")

    system_temp = r'C:\Windows\Temp'
    if os.path.isdir(system_temp):
        temp_folders_to_clean.append(system_temp)
    else:
        rprint(f"[yellow]    Warning: Folder {system_temp} not found or not a directory.[/yellow]")
        logging.warning(f"Folder {system_temp} not found.")

    temp_cleaned_at_least_one_folder = False
    for folder in temp_folders_to_clean:
        rprint(f"    Cleaning: {folder}")
        logging.info(f"Cleaning folder: {folder}")
        items_removed_count = 0
        items_error_count = 0
        try:
            for item_name in os.listdir(folder):
                item_path = os.path.join(folder, item_name)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.unlink(item_path)
                        items_removed_count += 1
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path, ignore_errors=True) # Try to remove, ignore errors for files in use
                        # Check if it was actually removed
                        if not os.path.exists(item_path):
                            items_removed_count +=1
                        else: # If it still exists, likely in use
                            logging.warning(f"Directory {item_path} could not be completely removed (likely in use).")
                            items_error_count +=1
                except PermissionError:
                    logging.warning(f"Permission denied to remove: {item_path}")
                    items_error_count += 1
                except OSError as e: # Other errors like "file in use"
                    logging.warning(f"OS error when trying to remove {item_path} (may be in use): {e}")
                    items_error_count += 1
                except Exception as e:
                    logging.warning(f"Unexpected error processing {item_path}: {e}")
                    items_error_count += 1

            if items_error_count > 0:
                rprint(f"    [yellow]Completed with {items_error_count} error(s) in '{folder}'. {items_removed_count} item(s) removed. (see log)[/yellow]")
            else:
                rprint(f"    [green]Cleaning of '{folder}' completed. {items_removed_count} item(s) removed.[/green]")
            if items_removed_count > 0 or items_error_count == 0 : # Consider success if something was removed or no errors
                temp_cleaned_at_least_one_folder = True

        except Exception as e:
            rprint(f"    [bold red]Error listing or cleaning {folder}: {e}[/bold red]")
            logging.error(f"Error cleaning {folder}: {e}")
            # Not incrementing tasks_failed here, as it's handled by items_error_count

    if temp_cleaned_at_least_one_folder : tasks_done +=1
    elif temp_folders_to_clean: tasks_failed +=1 # If tried and no folder was successfully cleaned


    # 3. Clean Component Store (WinSxS) with DISM
    rprint("\n[cyan]▶️ Running component store cleanup (DISM)... This may take a while.[/cyan]")
    dism_cleanup_command = ["DISM.exe", "/Online", "/Cleanup-Image", "/StartComponentCleanup"]
    result_dism_cleanup = run_command(dism_cleanup_command, capture=True)
    if result_dism_cleanup and result_dism_cleanup.returncode == 0:
        rprint("[bold green]    Component store cleanup (DISM) completed successfully![/bold green]")
        logging.info("DISM StartComponentCleanup completed successfully.")
        tasks_done +=1
    elif result_dism_cleanup and result_dism_cleanup.returncode == 3010: # ERROR_SUCCESS_REBOOT_REQUIRED
        rprint("[bold yellow]    Component store cleanup (DISM) completed. Reboot required to finalize.[/bold yellow]")
        logging.info("DISM StartComponentCleanup completed with code 3010 (Reboot required).")
        tasks_done +=1
    elif result_dism_cleanup: # Other error
        rprint("[bold red]    Failed component store cleanup (DISM).[/bold red]")
        logging.error(f"DISM StartComponentCleanup failed. Code: {result_dism_cleanup.returncode}")
        if result_dism_cleanup.stderr: rprint(f"[red]    Error: {result_dism_cleanup.stderr.strip()}[/red]")
        elif result_dism_cleanup.stdout: rprint(f"[red]    Output/Error: {result_dism_cleanup.stdout.strip()}[/red]")
        tasks_failed +=1
    else: # Command did not execute
        rprint("[bold red]    Failed to execute DISM cleanup command.[/bold red]")
        logging.error("Failed to start DISM StartComponentCleanup command.")
        tasks_failed +=1

    rprint("-" * 30)
    if tasks_failed == 0 and tasks_done > 0:
        rprint("[bold green]✅ General disk/cache cleanup completed successfully![/bold green]")
    elif tasks_done > 0:
        rprint(f"[bold yellow]⚠️ General disk/cache cleanup completed with {tasks_failed} failure(s) and {tasks_done} task(s) executed successfully (or partially). Check the log.[/bold yellow]")
    else:
        rprint(f"[bold red]❌ General disk/cache cleanup completed with {tasks_failed} failure(s) and no successful tasks.[/bold red]")


def optimize_memory():
    """Identifies and offers to terminate processes consuming a lot of memory."""
    clear_console()
    rprint(Panel("[bold cyan]🧠 Memory Optimizer (RAM Tweaker)[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting memory optimization.")
    rprint("[yellow]Warning: Terminating incorrect processes can cause system instability. Proceed with caution.[/yellow]")
    rprint("Searching for processes with high memory consumption...")

    processes_to_consider = []
    # Added English equivalents for system user names
    system_users_upper = {'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'}
    current_pid = os.getpid()
    windows_path_lower = os.environ.get('SystemRoot', 'C:\\Windows').lower()
    allowed_windows_procs_lower = {'explorer.exe'} # Processes in C:\Windows that can be closed
    critical_processes_lower = {
        'csrss.exe', 'wininit.exe', 'winlogon.exe', 'lsass.exe', 'smss.exe',
        'services.exe', 'svchost.exe', 'runtimebroker.exe', 'fontdrvhost.exe',
        'dwm.exe', 'ctfmon.exe', 'sihost.exe', 'taskhostw.exe'
    } # Add more known critical processes

    try:
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'username', 'exe']):
            try:
                pinfo = proc.info
                if not all(k in pinfo and pinfo[k] is not None for k in ['pid', 'name', 'memory_info']):
                    continue
                # Check for both original Portuguese and added English system user names
                if pinfo['username'] and (pinfo['username'].upper() in system_users_upper or
                                          pinfo['username'].upper() in {'SERVIÇO LOCAL', 'SERVIÇO DE REDE'}): # Keep PT for safety on some systems
                    continue
                if not pinfo['name'] or pinfo['pid'] == current_pid or pinfo['name'].lower() in ['python.exe', 'pythonw.exe', 'idle.exe', 'py.exe']:
                    continue
                if pinfo['name'].lower() in critical_processes_lower:
                    continue

                # Check for processes in C:\Windows
                # If 'exe' is None or empty, we can't do this check and might consider the process.
                if pinfo['exe']:
                    exe_path_lower = pinfo['exe'].lower()
                    if exe_path_lower.startswith(windows_path_lower) and \
                       pinfo['name'].lower() not in allowed_windows_procs_lower:
                        continue

                if pinfo['memory_info']:
                    mem_mb = pinfo['memory_info'].rss / (1024 * 1024)
                    if mem_mb > 50: # Consider processes above 50MB
                        processes_to_consider.append({
                            'pid': pinfo['pid'],
                            'name': pinfo['name'],
                            'memory_mb': mem_mb,
                            'username': pinfo['username'] or "N/A" # Handle None username
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e_inner:
                logging.warning(f"Error processing info for PID {proc.pid if proc else 'N/A'}: {e_inner}")

        if not processes_to_consider:
            rprint("[green]✅ No non-essential processes with high memory consumption (>50MB) found for optimization.[/green]")
            logging.info("No candidate processes for memory optimization found.")
            return

        processes_to_consider.sort(key=lambda x: x['memory_mb'], reverse=True)

        table = Table(title="🎮 Processes with High Memory Consumption (Suggestions to Terminate)", show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Process Name", style="cyan", min_width=20, overflow="fold")
        table.add_column("PID", style="green", width=8, justify="right")
        table.add_column("Memory (MB)", style="yellow", width=12, justify="right")
        table.add_column("User", style="blue", min_width=15, overflow="fold")

        display_limit = 20
        for idx, p_data in enumerate(processes_to_consider[:display_limit], 1):
            table.add_row(str(idx), p_data['name'], str(p_data['pid']), f"{p_data['memory_mb']:.2f}", p_data['username'])

        if len(processes_to_consider) > display_limit:
            rprint(f"[dim](Displaying top {display_limit} processes. Total found: {len(processes_to_consider)})[/dim]")

        console.print(table)
        rprint("\n[bold]👉 Enter the numbers (#) of the processes you want to terminate (separated by comma), or '0' to cancel:[/bold]")

        try:
            user_input = input("> ").strip()
            if user_input == '0' or not user_input:
                rprint("[yellow]⏩ Operation cancelled by user.[/yellow]")
                logging.info("Memory optimization cancelled by user.")
                return

            selected_indices = []
            raw_indices = user_input.split(',')
            for i_str in raw_indices:
                i_str = i_str.strip()
                if i_str.isdigit():
                    index_val = int(i_str) - 1
                    if 0 <= index_val < min(len(processes_to_consider), display_limit):
                        selected_indices.append(index_val)
                    else:
                        rprint(f"[red]    Invalid number ignored: {index_val + 1} (out of displayed range)[/red]")
                        logging.warning(f"Invalid index for terminating process: {index_val + 1}")
                elif i_str:
                    rprint(f"[red]    Invalid input ignored: '{i_str}'[/red]")
                    logging.warning(f"Non-numeric input for terminating process: '{i_str}'")

            if not selected_indices:
                rprint("[yellow]No valid processes selected to terminate.[/yellow]")
                return

            killed_count = 0
            error_count = 0
            for index in selected_indices:
                proc_to_kill = processes_to_consider[index]
                pid_to_kill = proc_to_kill['pid']
                proc_name = proc_to_kill['name']
                rprint(f"    Terminating: {proc_name} (PID: {pid_to_kill})...")
                logging.info(f"Attempting to terminate PID: {pid_to_kill}, Name: {proc_name}")

                try:
                    process_obj = psutil.Process(pid_to_kill)
                    process_obj.terminate() # Try to terminate gracefully
                    # Wait a bit to see if it terminates
                    try:
                        process_obj.wait(timeout=2) # Wait up to 2 seconds
                        rprint(f"    [green]Process {proc_name} (PID: {pid_to_kill}) terminated successfully (terminate).[/green]")
                        logging.info(f"Process PID {pid_to_kill} ({proc_name}) terminated via psutil.terminate().")
                        killed_count += 1
                    except psutil.TimeoutExpired:
                        rprint(f"    [yellow]Process {proc_name} (PID: {pid_to_kill}) did not terminate with 'terminate', trying to force (kill)...[/yellow]")
                        logging.warning(f"psutil.terminate() for PID {pid_to_kill} ({proc_name}) timed out. Trying kill().")
                        process_obj.kill()
                        process_obj.wait(timeout=1) # Short wait for kill
                        rprint(f"    [green]Process {proc_name} (PID: {pid_to_kill}) forced to terminate (kill).[/green]")
                        logging.info(f"Process PID {pid_to_kill} ({proc_name}) terminated via psutil.kill().")
                        killed_count +=1
                except psutil.NoSuchProcess:
                    rprint(f"    [yellow]Process {proc_name} (PID: {pid_to_kill}) not found (may have already been terminated).[/yellow]")
                    logging.warning(f"Process PID {pid_to_kill} ({proc_name}) not found when trying to terminate with psutil.")
                except psutil.AccessDenied:
                    rprint(f"    [red]Access denied to terminate {proc_name} (PID: {pid_to_kill}). Try as administrator or the process is protected.[/red]")
                    logging.error(f"Access denied when trying to terminate PID {pid_to_kill} ({proc_name}) with psutil.")
                    error_count += 1
                except Exception as e_kill:
                    rprint(f"    [red]Error trying to terminate {proc_name} (PID: {pid_to_kill}): {e_kill}[/red]")
                    logging.error(f"Error terminating PID {pid_to_kill} ({proc_name}) with psutil: {e_kill}")
                    error_count += 1

            rprint("-" * 30)
            if error_count == 0 and killed_count > 0:
                rprint(f"[bold green]✅ Memory optimization completed. {killed_count} process(es) terminated.[/bold green]")
            elif killed_count > 0:
                rprint(f"[bold yellow]⚠️ Memory optimization completed. {killed_count} process(es) terminated, {error_count} error(s) or warnings. Check the log.[/bold yellow]")
            else:
                rprint(f"[bold red]❌ Memory optimization completed. No processes successfully terminated, {error_count} error(s) or warnings.[/bold red]")
            logging.info(f"Memory optimization: {killed_count} terminated, {error_count} errors/warnings.")

        except ValueError:
            rprint("[bold red]Invalid input. Please enter numbers separated by comma or '0'.[/bold red]")
            logging.error("Invalid user input for process selection (ValueError).")
        except Exception as e:
            rprint(f"[bold red]Unexpected error during selection/termination: {e}[/bold red]")
            logging.exception("Unexpected error in memory optimization.")

    except Exception as e:
        rprint(f"[bold red]Error listing processes: {e}[/bold red]")
        logging.exception("Error listing processes for memory optimization.")


def optimize_startup():
    """Lists and allows disabling startup programs via Registry."""
    clear_console()
    rprint(Panel("[bold cyan]🚀 Startup Optimizer (Registry)[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting startup optimization.")
    rprint("[yellow]Warning: Disabling incorrect startup programs can affect the system. Proceed with caution.[/yellow]")

    startup_items = []
    for hkey, key_path in STARTUP_REG_KEYS:
        try:
            with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                        if value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                            item_id = f"{value_name.lower()}|{str(value_data).lower()}"
                            is_duplicate = any(f"{item['name'].lower()}|{str(item['command']).lower()}" == item_id for item in startup_items)
                            if not is_duplicate:
                                startup_items.append({
                                    'name': value_name, 'command': value_data, 'hkey': hkey,
                                    'key_path': key_path,
                                    'source': "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM",
                                })
                        index += 1
                    except OSError: break # End of values
        except FileNotFoundError:
            logging.info(f"Startup key not found (ignoring): {key_path}")
        except PermissionError:
            rprint(f"[red]    Permission error when reading key: {key_path}. Some items may not be listed.[/red]")
            logging.error(f"Permission denied when reading startup key: {key_path}")
        except Exception as e:
            rprint(f"[red]    Unexpected error reading key {key_path}: {e}[/red]")
            logging.exception(f"Unexpected error reading startup key: {key_path}")

    if not startup_items:
        rprint("[green]✅ No startup programs found in common registry keys.[/green]")
        logging.info("No startup items found.")
        return

    startup_items.sort(key=lambda x: (x['source'], x['name'].lower()))

    table = Table(title="💻 Startup Programs (Registry)", show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Name", style="cyan", min_width=20)
    table.add_column("Command / Path", style="green", max_width=60, overflow="fold")
    table.add_column("Registry Location", style="blue", max_width=40, overflow="fold")

    for idx, item in enumerate(startup_items, 1):
        key_name_only = os.path.basename(item['key_path'])
        wow_marker = " (Wow64)" if "Wow6432Node" in item['key_path'] else ""
        reg_location = f"{item['source']}\\{key_name_only}{wow_marker}"
        table.add_row(str(idx), item['name'], str(item['command']), reg_location)

    console.print(table)
    rprint("\n[bold]👉 Enter the numbers (#) of the programs you want to disable (removing from registry) (separated by comma), or '0' to cancel:[/bold]")

    try:
        user_input = input("> ").strip()
        if user_input == '0' or not user_input:
            rprint("[yellow]⏩ Operation cancelled by user.[/yellow]")
            logging.info("Startup optimization cancelled.")
            return

        selected_indices = []
        raw_indices = user_input.split(',')
        for i_str in raw_indices:
            i_str = i_str.strip()
            if i_str.isdigit():
                index_val = int(i_str) - 1
                if 0 <= index_val < len(startup_items):
                    selected_indices.append(index_val)
                else:
                    rprint(f"[red]    Invalid number ignored: {index_val + 1}[/red]")
            elif i_str: rprint(f"[red]    Invalid input ignored: '{i_str}'[/red]")

        if not selected_indices:
            rprint("[yellow]No valid programs selected to disable.[/yellow]")
            return

        disabled_count = 0
        error_count = 0
        for index in selected_indices:
            item_to_disable = startup_items[index]
            name = item_to_disable['name']
            hkey_root = item_to_disable['hkey']
            key_path_str = item_to_disable['key_path']

            rprint(f"    Disabling: {name}...")
            logging.info(f"Attempting to disable '{name}' from '{key_path_str}'")
            try:
                with winreg.OpenKey(hkey_root, key_path_str, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                    winreg.DeleteValue(key, name)
                rprint(f"    [green]'{name}' disabled successfully.[/green]")
                logging.info(f"'{name}' disabled from '{key_path_str}'.")
                disabled_count += 1
            except FileNotFoundError:
                rprint(f"    [red]Error: Item '{name}' not found in '{key_path_str}' (may have already been removed).[/red]")
                logging.error(f"'{name}' not found in '{key_path_str}' when trying to delete.")
                error_count += 1
            except PermissionError:
                rprint(f"    [bold red]Permission error when disabling '{name}'.[/bold red]")
                logging.error(f"Permission denied to delete '{name}' from '{key_path_str}'.")
                error_count += 1
            except Exception as e:
                rprint(f"    [bold red]Unexpected error disabling '{name}': {e}[/bold red]")
                logging.exception(f"Error disabling '{name}' from '{key_path_str}'.")
                error_count += 1

        rprint("-" * 30)
        if error_count == 0 and disabled_count > 0:
            rprint(f"[bold green]✅ Startup optimization completed. {disabled_count} program(s) disabled.[/bold green]")
        elif disabled_count > 0:
            rprint(f"[bold yellow]⚠️ Startup optimization: {disabled_count} disabled, {error_count} error(s). Check log.[/bold yellow]")
        else:
            rprint(f"[bold red]❌ Startup optimization: No programs disabled, {error_count} error(s).[/bold red]")
        logging.info(f"Startup optimization: {disabled_count} disabled, {error_count} errors.")

    except ValueError:
        rprint("[bold red]Invalid input.[/bold red]")
        logging.error("Invalid user input for startup optimization (ValueError).")
    except Exception as e:
        rprint(f"[bold red]Unexpected error: {e}[/bold red]")
        logging.exception("Unexpected error in startup optimization.")


def optimize_visuals():
    """Applies visual settings for best performance."""
    clear_console()
    rprint(Panel("[bold cyan]🎨 Adjusting Visual Effects for Best Performance...[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting adjustment of visual effects.")

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, VISUAL_EFFECTS_KEY_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, VISUAL_EFFECTS_VALUE_NAME, 0, winreg.REG_DWORD, VISUAL_EFFECTS_BEST_PERFORMANCE_VALUE)
        rprint("[green]'VisualFXSetting' set to Best Performance (Value=2).[/green]")
        logging.info(f"'{VISUAL_EFFECTS_VALUE_NAME}' set to {VISUAL_EFFECTS_BEST_PERFORMANCE_VALUE} in 'HKCU\\{VISUAL_EFFECTS_KEY_PATH}'.")
        rprint("[yellow]Note: Windows will apply the corresponding detailed settings.[/yellow]")
        rprint("[bold green]✅ Visual adjustments for best performance applied successfully![/bold green]")
        rprint("[yellow i]You may need to log out or restart your computer for all changes to take full effect.[/yellow i]")
        logging.info("Visual effects adjustment completed.")
    except FileNotFoundError:
        rprint(f"[bold red]❌ Error: Registry key not found: HKCU\\{VISUAL_EFFECTS_KEY_PATH}[/bold red]")
        logging.error(f"Registry key not found: HKCU\\{VISUAL_EFFECTS_KEY_PATH}")
    except PermissionError:
        rprint("[bold red]❌ Permission error modifying the registry. Run as administrator.[/bold red]")
        logging.error("Permission denied when modifying visual effects key.")
    except Exception as e:
        rprint(f"[bold red]❌ Unexpected error adjusting visual effects: {e}[/bold red]")
        logging.exception("Unexpected error adjusting visual effects.")

def set_menu_show_delay():
    """Adjusts the menu display delay in Windows."""
    clear_console()
    rprint(Panel("[bold cyan]⏱️ Adjusting Menu Display Delay...[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting MenuShowDelay adjustment.")

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, MENU_SHOW_DELAY_KEY_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, MENU_SHOW_DELAY_VALUE_NAME, 0, winreg.REG_SZ, MENU_SHOW_DELAY_FAST_VALUE)
        rprint(f"[green]Menu delay ('MenuShowDelay') set to '{MENU_SHOW_DELAY_FAST_VALUE}' ms.[/green]")
        logging.info(f"'{MENU_SHOW_DELAY_VALUE_NAME}' set to '{MENU_SHOW_DELAY_FAST_VALUE}' in 'HKCU\\{MENU_SHOW_DELAY_KEY_PATH}'.")
        rprint("[bold green]✅ Menu delay adjustment applied successfully![/bold green]")
        rprint("[yellow i]You may need to log out or restart for the change to take full effect.[/yellow i]")
        logging.info("MenuShowDelay adjustment completed.")
    except FileNotFoundError:
        rprint(f"[bold red]❌ Error: Registry key not found: HKCU\\{MENU_SHOW_DELAY_KEY_PATH}[/bold red]")
        logging.error(f"Registry key not found for MenuShowDelay: HKCU\\{MENU_SHOW_DELAY_KEY_PATH}")
    except PermissionError:
        rprint("[bold red]❌ Permission error modifying the registry for MenuShowDelay. Run as administrator.[/bold red]")
        logging.error("Permission denied when modifying MenuShowDelay.")
    except Exception as e:
        rprint(f"[bold red]❌ Unexpected error adjusting MenuShowDelay: {e}[/bold red]")
        logging.exception("Unexpected error adjusting MenuShowDelay.")


def set_power_plan():
    """Activates the High Performance or Ultimate Performance power plan."""
    clear_console()
    rprint(Panel("[bold cyan]⚡ Setting Optimized Power Plan...[/bold cyan]", title="⚙️ Optimization", border_style="magenta"))
    logging.info("Starting power plan setting.")

    activated_plan_name = None

    # 1. Try to enable (duplicate) the Ultimate Performance plan
    rprint("[cyan]▶️ Trying to enable 'Ultimate Performance' plan...[/cyan]")
    duplicate_command = ["powercfg", "-duplicatescheme", GUID_ULTIMATE_PERFORMANCE]
    result_dup = run_command(duplicate_command, capture=True, check_ret=False) # Don't fail if it already exists

    parsed_guid_ultimate = None
    if result_dup and result_dup.returncode == 0 and result_dup.stdout:
        # Regex for English output
        match_en = re.search(r"Power Scheme GUID:\s*([a-f0-9-]+)\s*\(Ultimate Performance\)", result_dup.stdout, re.IGNORECASE)
        # Regex for Portuguese output
        match_pt = re.search(r"GUID do Esquema de Energia:\s*([a-f0-9-]+)\s*\(Desempenho Máximo\)", result_dup.stdout, re.IGNORECASE)
        match = match_en or match_pt

        if match:
            parsed_guid_ultimate = match.group(1).strip()
            rprint(f"[green]    'Ultimate Performance' plan duplicated/found. GUID: {parsed_guid_ultimate}[/green]")
            logging.info(f"Ultimate Performance plan duplicated/verified. GUID: {parsed_guid_ultimate}")
        # Check for both English and Portuguese "already exists" messages
        elif "already exists" in (result_dup.stdout or "").lower() or "já existe" in (result_dup.stdout or "").lower():
            rprint("[yellow]    'Ultimate Performance' plan already exists. Will try to use it.[/yellow]")
            logging.info("Ultimate Performance already exists, using default GUID.")
            # If it already exists, we will try to find its GUID in the listing
        else:
            rprint("[yellow]    Could not confirm 'Ultimate Performance' plan GUID from duplication. Output: " + (result_dup.stdout or "N/A").strip() + "[/yellow]")
            logging.warning(f"Could not extract GUID from Ultimate Performance duplication. Output: {(result_dup.stdout or '').strip()}")
    elif result_dup and result_dup.stderr:
        rprint(f"[yellow]    Warning when trying to duplicate 'Ultimate Performance': {(result_dup.stderr or '').strip()}[/yellow]")
        logging.warning(f"Failure/warning duplicating Ultimate Performance: {(result_dup.stderr or '').strip()}")

    # 2. List plans and try to activate
    rprint("\n[cyan]▶️ Listing available power plans...[/cyan]")
    list_command = ["powercfg", "/list"]
    result_list = run_command(list_command, capture=True)

    if result_list and result_list.returncode == 0 and result_list.stdout:
        plans = {}
        current_active_guid = None
        for line in result_list.stdout.splitlines():
            # Regex for English output
            match_plan_en = re.match(r"Power Scheme GUID:\s*([a-f0-9-]+)\s*\((.+?)\)(\s*\*?)", line.strip(), re.IGNORECASE)
            # Regex for Portuguese output
            match_plan_pt = re.match(r"GUID do Esquema de Energia:\s*([a-f0-9-]+)\s*\((.+?)\)(\s*\*?)", line.strip(), re.IGNORECASE)
            match_plan = match_plan_en or match_plan_pt

            if match_plan:
                guid, name, active_marker = match_plan.groups()
                guid = guid.strip()
                name = name.strip()
                plans[guid] = name
                if active_marker.strip() == "*":
                    current_active_guid = guid
            elif line.strip() and "Power Scheme GUID:" not in line and "GUID do Esquema de Energia:" not in line : # Ignore headers
                logging.debug(f"Unparsed line from powercfg /list: {line.strip()}")


        if not plans:
            rprint("[red]    Could not find any power plans.[/red]")
            logging.error("No power plans found after parsing 'powercfg /list'.")
            return

        rprint("    Plans found:")
        for guid_item, name_item in plans.items():
            active_str = " [bold cyan](Active)[/bold cyan]" if guid_item == current_active_guid else ""
            rprint(f"        - {name_item} (GUID: {guid_item}){active_str}")

        # Determine which plan to activate (Ultimate > High > Original)
        guid_to_set = None
        desired_plan_name = ""

        # Try Ultimate (by parsed GUID from duplication, or by default GUID)
        if parsed_guid_ultimate and parsed_guid_ultimate in plans:
            guid_to_set = parsed_guid_ultimate
            desired_plan_name = plans[guid_to_set]
        elif GUID_ULTIMATE_PERFORMANCE in plans:
            guid_to_set = GUID_ULTIMATE_PERFORMANCE
            desired_plan_name = plans[guid_to_set]
        # Also check for Portuguese name of Ultimate Performance if GUIDs differ
        elif any(name.lower() == "desempenho máximo" for name in plans.values()):
             for g, n in plans.items():
                if n.lower() == "desempenho máximo":
                    guid_to_set = g
                    desired_plan_name = n
                    break


        # If Ultimate was not found/activated, try High Performance
        if not guid_to_set and GUID_HIGH_PERFORMANCE in plans:
            guid_to_set = GUID_HIGH_PERFORMANCE
            desired_plan_name = plans[guid_to_set]
        # Also check for Portuguese name of High Performance
        elif not guid_to_set and any(name.lower() == "alto desempenho" for name in plans.values()):
            for g, n in plans.items():
                if n.lower() == "alto desempenho":
                    guid_to_set = g
                    desired_plan_name = n
                    break


        if guid_to_set:
            if guid_to_set == current_active_guid:
                rprint(f"\n[green]✅ Plan '{desired_plan_name}' is already active.[/green]")
                logging.info(f"Plan '{desired_plan_name}' (GUID: {guid_to_set}) was already active.")
                activated_plan_name = desired_plan_name
            else:
                rprint(f"\n[cyan]▶️ Trying to activate '{desired_plan_name}'...[/cyan]")
                activate_command = ["powercfg", "/setactive", guid_to_set]
                result_activate = run_command(activate_command, capture=True)
                if result_activate and result_activate.returncode == 0:
                    rprint(f"[bold green]✅ Plan '{desired_plan_name}' activated successfully![/bold green]")
                    logging.info(f"Plan '{desired_plan_name}' (GUID: {guid_to_set}) activated.")
                    activated_plan_name = desired_plan_name
                else:
                    rprint(f"[red]    Failed to activate '{desired_plan_name}'. Check the log.[/red]")
                    err_details = (result_activate.stderr or result_activate.stdout or "N/A").strip()
                    logging.error(f"Failed to activate plan '{desired_plan_name}' (GUID: {guid_to_set}). Details: {err_details}")

        if not activated_plan_name:
            rprint("\n[bold red]❌ Could not activate an optimized power plan (Ultimate Performance or High Performance).[/bold red]")
            rprint("[yellow]    Your current plan remains active. Check if the plans exist or if there are errors in the log.[/yellow]")
            logging.error("No high-performance plan could be activated.")
    else:
        rprint("[bold red]❌ Failed to list power plans.[/bold red]")
        err_details = (result_list.stderr or result_list.stdout or "N/A").strip()
        logging.error(f"Failed to execute 'powercfg /list'. Details: {err_details}")

# --- New Functions ---

def get_defender_path():
    """Tries to find the path of MpCmdRun.exe."""
    # Common paths, the second is for newer versions of the Defender platform
    paths_to_check = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Windows Defender", "MpCmdRun.exe"),
        os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "Microsoft\\Windows Defender\\Platform")
        # For the second path, we need to find the latest version subfolder
    ]

    if os.path.exists(paths_to_check[0]):
        return paths_to_check[0]

    # Logic for the second path (platform)
    platform_base_path = paths_to_check[1]
    if os.path.isdir(platform_base_path):
        versions = [d for d in os.listdir(platform_base_path) if os.path.isdir(os.path.join(platform_base_path, d))]
        if versions:
            # Try to sort by modification date or name (assuming version names are sortable)
            versions.sort(key=lambda v: os.path.getmtime(os.path.join(platform_base_path, v)), reverse=True) # Latest by date
            # Or by version name, if it's numeric with dots
            # versions.sort(key=lambda v: [int(part) for part in v.split('.')], reverse=True)

            latest_version_path = os.path.join(platform_base_path, versions[0], "MpCmdRun.exe")
            if os.path.exists(latest_version_path):
                return latest_version_path

    logging.warning("MpCmdRun.exe not found in default paths.")
    return None


def run_defender_scan_action(scan_type_code, scan_type_name_en):
    """Runs a Windows Defender scan (Quick or Full)."""
    clear_console()
    rprint(Panel(f"[bold cyan]🛡️ Starting Windows Defender {scan_type_name_en} Scan...[/bold cyan]", title="🛡️ Antivirus", border_style="magenta"))
    logging.info(f"Starting Windows Defender {scan_type_name_en} scan.")

    defender_path = get_defender_path()
    if not defender_path:
        rprint("[bold red]❌ MpCmdRun.exe (Windows Defender CLI) not found. Cannot start scan.[/bold red]")
        return

    rprint(f"[dim]Using MpCmdRun.exe at: {defender_path}[/dim]")

    # 1. Update signatures
    rprint("\n[cyan]▶️ Trying to update virus definitions...[/cyan]")
    update_command = [defender_path, "-SignatureUpdate"]
    result_update = run_command(update_command, capture=True)
    if result_update and result_update.returncode == 0:
        rprint("[green]    Virus definitions updated or already up-to-date.[/green]")
        logging.info("Defender signature update completed or not necessary.")
    elif result_update: # Failed update, but continue with scan
        rprint(f"[yellow]    Warning: Failed to update definitions (Code: {result_update.returncode}). Scan will continue with current definitions.[/yellow]")
        if result_update.stderr: rprint(f"[dim yellow]        Error: {result_update.stderr.strip()}[/dim yellow]")
        logging.warning(f"Failed to update Defender signatures. Code: {result_update.returncode}. Error: {(result_update.stderr or '').strip()}")
    else: # Command did not execute
        rprint("[yellow]    Warning: Could not execute definition update. Scan will continue.[/yellow]")
        logging.warning("Failed to start Defender signature update command.")


    # 2. Run scan
    rprint(f"\n[cyan]▶️ Starting {scan_type_name_en} Scan... This may take a considerable time.[/cyan]")
    rprint("[yellow]    The prompt window may seem frozen. Actual progress can be seen in Windows Defender notifications.[/yellow]")
    scan_command = [defender_path, "-Scan", "-ScanType", str(scan_type_code)]

    # Use Popen to run in the background and not block the script, as scans can be long.
    # It's not easy to capture the "end" simply with MpCmdRun.exe.
    try:
        process = subprocess.Popen(scan_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info(f"Defender {scan_type_name_en} scan command started (PID: {process.pid}).")
        rprint(f"[green]    {scan_type_name_en} scan started in the background.[/green]")
        rprint("[cyan i]    Please monitor the scan status through the Windows Defender interface or system notifications.[/cyan i]")
        rprint("[yellow i]    This window will not show real-time progress.[/yellow i]")
        # Here we could have a loop that checks if the process ended, but MpCmdRun
        # might return immediately and the scan continue in a Defender service.
        # For simplicity, we just start it.
    except Exception as e:
        rprint(f"[bold red]❌ Failed to start {scan_type_name_en} Scan: {e}[/bold red]")
        logging.exception(f"Failed to start Defender {scan_type_name_en} scan.")

def run_defender_quick_scan():
    run_defender_scan_action(1, "Quick")

def run_defender_full_scan():
    run_defender_scan_action(2, "Full")


def flush_dns_cache():
    """Clears the system's DNS cache."""
    clear_console()
    rprint(Panel("[bold cyan]🌐 Clearing DNS Cache...[/bold cyan]", title="⚙️ Network Optimization", border_style="magenta"))
    logging.info("Starting DNS cache cleanup.")

    command = ["ipconfig", "/flushdns"]
    result = run_command(command, capture=True)

    if result and result.returncode == 0:
        # Success message can vary by system language.
        # English: "Successfully flushed the DNS Resolver Cache."
        # Portuguese: "Liberação do cache do DNS Resolver bem-sucedida."
        if "Successfully flushed" in result.stdout or "bem-sucedida" in result.stdout:
            rprint("[bold green]✅ DNS Cache cleared successfully![/bold green]")
            logging.info("DNS Cache cleared successfully.")
        else:
            rprint(f"[bold yellow]⚠️ Command executed, but success message was not standard. Check output:[/bold yellow]\n[dim]{result.stdout.strip()}[/dim]")
            logging.warning(f"ipconfig /flushdns executed, but message not standard: {result.stdout.strip()}")
    elif result:
        rprint("[bold red]❌ Failed to clear DNS cache.[/bold red]")
        if result.stderr: rprint(f"[red]    Error: {result.stderr.strip()}[/red]")
        elif result.stdout: rprint(f"[red]    Output/Error: {result.stdout.strip()}[/red]")
        logging.error(f"Failed to clear DNS cache. Code: {result.returncode}. Error: {(result.stderr or result.stdout or '').strip()}")
    else:
        rprint("[bold red]❌ Failed to execute DNS cache clear command.[/bold red]")
        logging.error("Failed to start ipconfig /flushdns command.")

def reset_network_settings():
    """Resets Winsock and TCP/IP settings."""
    clear_console()
    rprint(Panel("[bold cyan]🔄 Resetting Network Settings (Winsock and TCP/IP)...[/bold cyan]", title="⚙️ Network Optimization", border_style="magenta"))
    logging.info("Starting network settings reset.")
    rprint("[bold yellow]WARNING: This operation will reset your network settings to defaults and WILL REQUIRE A COMPUTER RESTART.[/bold yellow]")

    confirm = input("Do you want to continue? (y/N): ").strip().lower()
    if confirm != 'y': # Changed 's' to 'y' for English
        rprint("[yellow]Operation cancelled by user.[/yellow]")
        logging.info("Network reset cancelled by user.")
        return

    success_winsock = False
    success_tcpip = False

    # 1. Reset Winsock
    rprint("\n[cyan]▶️ Resetting Winsock catalog...[/cyan]")
    winsock_command = ["netsh", "winsock", "reset"]
    result_winsock = run_command(winsock_command, capture=True)
    if result_winsock and result_winsock.returncode == 0:
        rprint("[green]    Winsock reset completed successfully.[/green]")
        logging.info("netsh winsock reset completed successfully.")
        success_winsock = True
    elif result_winsock:
        rprint("[red]    Failed to reset Winsock.[/red]")
        if result_winsock.stderr: rprint(f"[red]        Error: {result_winsock.stderr.strip()}[/red]")
        elif result_winsock.stdout: rprint(f"[red]        Output/Error: {result_winsock.stdout.strip()}[/red]")
        logging.error(f"netsh winsock reset failed. Code: {result_winsock.returncode}. Details: {(result_winsock.stderr or result_winsock.stdout or '').strip()}")
    else:
        rprint("[red]    Failed to execute Winsock reset command.[/red]")
        logging.error("Failed to start netsh winsock reset.")

    # 2. Reset TCP/IP
    rprint("\n[cyan]▶️ Resetting TCP/IP stack...[/cyan]")
    tcpip_command = ["netsh", "int", "ip", "reset"] # The log is optional, not essential for the script
    result_tcpip = run_command(tcpip_command, capture=True)
    if result_tcpip and result_tcpip.returncode == 0:
        rprint("[green]    TCP/IP reset completed successfully.[/green]")
        logging.info("netsh int ip reset completed successfully.")
        success_tcpip = True
    elif result_tcpip:
        rprint("[red]    Failed to reset TCP/IP.[/red]")
        if result_tcpip.stderr: rprint(f"[red]        Error: {result_tcpip.stderr.strip()}[/red]")
        elif result_tcpip.stdout: rprint(f"[red]        Output/Error: {result_tcpip.stdout.strip()}[/red]")
        logging.error(f"netsh int ip reset failed. Code: {result_tcpip.returncode}. Details: {(result_tcpip.stderr or result_tcpip.stdout or '').strip()}")
    else:
        rprint("[red]    Failed to execute TCP/IP reset command.[/red]")
        logging.error("Failed to start netsh int ip reset.")

    rprint("-" * 30)
    if success_winsock and success_tcpip:
        rprint("[bold green]✅ Network reset completed. Please RESTART your computer to apply changes.[/bold green]")
    else:
        rprint("[bold red]❌ Network reset completed with one or more failures. Check the log. If anything was reset, a restart may still be necessary.[/bold red]")

def toggle_hibernation_option(enable: bool):
    """Enables or Disables hibernation."""
    action_verb_ing = "Enabling" if enable else "Disabling"
    action_verb_ed = "Enabled" if enable else "Disabled" # For success message
    command_suffix = "on" if enable else "off"
    clear_console()
    rprint(Panel(f"[bold cyan]⚙️ {action_verb_ing} System Hibernation...[/bold cyan]", title="⚙️ Power Management", border_style="magenta"))
    logging.info(f"{action_verb_ing} hibernation.")

    if enable:
        rprint("[cyan i]    This will recreate the hiberfil.sys file, which occupies disk space (usually equal to your RAM), but allows fast startup and hibernation.[/cyan i]")
    else:
        rprint("[cyan i]    This will remove the hiberfil.sys file, freeing up disk space, but will disable hibernation and fast startup.[/cyan i]")

    hiber_command = ["powercfg.exe", "/hibernate", command_suffix]
    result = run_command(hiber_command, capture=True)

    if result and result.returncode == 0:
        rprint(f"[bold green]✅ Hibernation {action_verb_ed.lower()} successfully![/bold green]")
        logging.info(f"Hibernation {action_verb_ed.lower()} successfully.")
    elif result:
        rprint(f"[bold red]❌ Failed to {action_verb_ing.lower().replace('ing','e')} hibernation.[/bold red]") # e.g. "enable"
        if result.stderr: rprint(f"[red]    Error: {result.stderr.strip()}[/red]")
        elif result.stdout: rprint(f"[red]    Output/Error: {result.stdout.strip()}[/red]")
        logging.error(f"Failed to {action_verb_ing.lower().replace('ing','e')} hibernation. Code: {result.returncode}. Details: {(result.stderr or result.stdout or '').strip()}")
    else:
        rprint(f"[bold red]❌ Failed to execute powercfg command for hibernation.[/bold red]")
        logging.error(f"Failed to start powercfg /hibernate {command_suffix} command.")

def enable_hibernation():
    toggle_hibernation_option(True)

def disable_hibernation():
    toggle_hibernation_option(False)

def clear_event_logs():
    """Clears Windows event logs."""
    clear_console()
    rprint(Panel("[bold cyan]🗑️ Clearing Windows Event Logs...[/bold cyan]", title="⚙️ Maintenance", border_style="magenta"))
    logging.info("Starting event log cleanup.")
    rprint("[bold red]WARNING: This action will clear major event logs (Application, System, Security, etc.).[/bold red]")
    rprint("[bold red]This can make it difficult to diagnose future problems if they occur immediately after cleaning.[/bold red]")

    confirm = input("Are you sure you want to clear ALL major event logs? (y/N): ").strip().lower()
    if confirm != 'y': # Changed 's' to 'y'
        rprint("[yellow]Operation cancelled by user.[/yellow]")
        logging.info("Event log cleanup cancelled.")
        return

    # Using PowerShell is cleaner for iterating and clearing logs
    ps_script = (
        "Write-Host 'Clearing event logs...'; "
        "Get-WinEvent -ListLog * | Where-Object {$_.IsEnabled -and $_.RecordCount -gt 0 -and $_.LogType -eq 'Operational' -and ($_.LogName -like 'Application' -or $_.LogName -like 'System' -or $_.LogName -like 'Security' -or $_.LogName -like 'Setup' -or $_.LogName -match 'Microsoft-Windows-.*/Operational')} | ForEach-Object { "
        "  Write-Host \"Clearing log: $($_.LogName)...\"; "
        "  try { Clear-EventLog -LogName $_.LogName -ErrorAction Stop } "
        "  catch { Write-Warning \"Failed to clear $($_.LogName): $($_.Exception.Message)\" } "
        "} ; Write-Host 'Event log cleanup attempt completed.'" # Translated message
    )
    # Another more aggressive option with wevtutil, but can generate errors for Debug/Analytic logs:
    # cmd_command_str = "for /F \"tokens=*\" %G in ('wevtutil.exe el') DO wevtutil.exe cl \"%G\""
    # To use in subprocess, %G needs to be %%G if shell=True, or handle iteration in Python.
    # For simplicity and better error control, PowerShell is preferable here.

    ps_command = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
    result = run_command(ps_command, capture=True, display_output=True) # display_output to see progress

    if result and result.returncode == 0:
        rprint("[bold green]✅ Attempt to clear major event logs completed.[/bold green]")
        rprint("[yellow i]Some logs may not have been cleared due to permissions or being in use. Check the output above and the system log.[/yellow i]")
        logging.info("Attempt to clear event logs completed successfully (via PowerShell).")
    elif result:
        rprint("[bold red]❌ Errors occurred during event log cleanup.[/bold red]")
        logging.error(f"Event log cleanup failed (via PowerShell). Code: {result.returncode}. Details in log and command output.")
    else:
        rprint("[bold red]❌ Failed to execute event log cleanup command.[/bold red]")
        logging.error("Failed to start PowerShell command for log cleanup.")


def run_system_maintenance():
    """Runs SFC /scannow and DISM /Online /Cleanup-Image /RestoreHealth."""
    clear_console()
    rprint(Panel("[bold cyan]🛠️ Running System Maintenance (SFC & DISM)...[/bold cyan]", title="⚙️ Maintenance", border_style="magenta"))
    logging.info("Starting system maintenance (SFC and DISM).")
    rprint("[yellow i]This process can take some time, and DISM may require an internet connection.[/yellow i]")

    sfc_success = False
    dism_success = False

    # 1. Run SFC /scannow
    rprint("\n[cyan]▶️ Running System File Checker (sfc /scannow)...[/cyan]")
    sfc_command = ["sfc", "/scannow"]
    result_sfc = run_command(sfc_command, capture=True, display_output=True)

    if result_sfc is not None and not isinstance(result_sfc, subprocess.CalledProcessError): # If run_command returned result and not exception
        sfc_output = (result_sfc.stdout or "") + (result_sfc.stderr or "")
        # Checking for both English and Portuguese success messages
        if "Windows Resource Protection did not find any integrity violations" in sfc_output or \
           "A Proteção de Recursos do Windows não encontrou nenhuma violação de integridade" in sfc_output:
            rprint("[green]    SFC: No integrity violations found.[/green]")
            sfc_success = True
        elif "Windows Resource Protection found corrupt files and successfully repaired them" in sfc_output or \
             "A Proteção de Recursos do Windows encontrou arquivos corrompidos e os reparou com êxito" in sfc_output:
            rprint("[green]    SFC: Corrupt files found and successfully repaired.[/green]")
            sfc_success = True
        elif "Windows Resource Protection found corrupt files but was unable to fix some of them" in sfc_output or \
             "A Proteção de Recursos do Windows encontrou arquivos corrompidos, mas não pôde corrigir alguns deles" in sfc_output:
            rprint("[bold red]    SFC: Corrupt files found, but some could NOT be repaired. Check CBS.log.[/bold red]")
        elif result_sfc.returncode == 0 : # Code 0, but unrecognized message
            rprint(f"[yellow]    SFC: Scan completed (Code 0). Check output in log {LOG_FILENAME}.[/yellow]")
            sfc_success = True # Assume success if code 0
        else:
            rprint(f"[red]    SFC: Scan completed with code {result_sfc.returncode}. Check output in log.[/red]")

        if sfc_success: logging.info("sfc /scannow command completed with indication of success or no errors.")
        else: logging.error(f"sfc /scannow command completed with code {result_sfc.returncode} or reported problems.")

    elif isinstance(result_sfc, subprocess.CalledProcessError): # If run_command raised and returned the exception
        rprint(f"[red]    SFC: Execution failed (Code {result_sfc.returncode}). Check output in log.[/red]")
        logging.error(f"SFC /scannow failed with CalledProcessError. Code: {result_sfc.returncode}")
    else: # Command not found
        rprint("[bold red]    Failed to execute sfc /scannow command.[/bold red]")
        logging.error("Failed to start sfc /scannow command (not found).")

    # 2. Run DISM /Online /Cleanup-Image /RestoreHealth
    rprint("\n[cyan]▶️ Running Windows Image Repair (DISM /RestoreHealth)... This may take a while.[/cyan]")
    dism_restore_command = ["DISM.exe", "/Online", "/Cleanup-Image", "/RestoreHealth"]
    result_dism_restore = run_command(dism_restore_command, capture=True, display_output=True)

    if result_dism_restore is not None and not isinstance(result_dism_restore, subprocess.CalledProcessError):
        dism_output = (result_dism_restore.stdout or "") + (result_dism_restore.stderr or "")
        # Checking for both English and Portuguese success messages
        if "The restore operation completed successfully" in dism_output or \
           "A operação de restauração foi concluída com êxito" in dism_output:
            rprint("[green]    DISM: Restore operation completed successfully.[/green]")
            dism_success = True
        elif "0x800f081f" in dism_output: # Common error: source not found
            rprint("[bold red]    DISM: Error 0x800f081f - Source files not found.[/bold red]")
            rprint("[yellow]        Check internet connection or provide a valid repair source (WIM/ESD).[/yellow]")
        elif result_dism_restore.returncode == 0: # Code 0 but unrecognized message
            rprint(f"[yellow]    DISM: Operation completed (Code 0). Check output in log {LOG_FILENAME}.[/yellow]")
            dism_success = True # Assume success if code 0
        elif result_dism_restore.returncode == 3010: # Reboot required
            rprint("[bold yellow]    DISM: Operation completed. Reboot required to finalize.[/bold yellow]")
            dism_success = True
        else: # Other error code
            rprint(f"[red]    DISM: Operation failed (Code {result_dism_restore.returncode}). Check output in log.[/red]")

        if dism_success : logging.info(f"DISM /RestoreHealth command completed with indication of success (Code: {result_dism_restore.returncode}).")
        else: logging.error(f"DISM /RestoreHealth command completed with code {result_dism_restore.returncode} or reported problems.")

    elif isinstance(result_dism_restore, subprocess.CalledProcessError):
        rprint(f"[red]    DISM: Execution failed (Code {result_dism_restore.returncode}). Check output in log.[/red]")
        logging.error(f"DISM /RestoreHealth failed with CalledProcessError. Code: {result_dism_restore.returncode}")
    else:
        rprint("[bold red]    Failed to execute DISM /RestoreHealth command.[/bold red]")
        logging.error("Failed to start DISM /RestoreHealth command (not found).")

    rprint("-" * 30)
    if sfc_success and dism_success:
        rprint("[bold green]✅ System maintenance (SFC and DISM) completed successfully.[/bold green]")
    else:
        rprint("[bold yellow]⚠️ System maintenance completed with possible errors or warnings. Check the output and log.[/bold yellow]")
        if not sfc_success: rprint("[yellow]        - SFC encountered problems or could not be confirmed as successful.[/yellow]")
        if not dism_success: rprint("[yellow]        - DISM encountered problems or could not be confirmed as successful.[/yellow]")


# --- Menu and Main Loop ---

def display_menu():
    """Displays the main menu of options."""
    clear_console()
    rprint(Panel(f"[bold dodger_blue1]{APP_TITLE}[/bold dodger_blue1]", title="[b gold1]Main Menu[/b gold1]", border_style="bright_magenta", expand=False, subtitle="Choose an option:"))

    menu_items = [
        ("1", "🛡️ Create Restore Point", "Creates a system backup before major changes."),
        ("2", "🧹 Clean Caches and Temporary Files", "Frees up space and removes system junk."),
        ("3", "🧠 Optimize Memory (RAM Tweaker)", "Closes unnecessary processes to free up RAM."),
        ("4", "🚀 Optimize Startup (Registry)", "Manages programs that start with Windows."),
        ("5", "🎨 Adjust Visual Effects (Best Performance)", "Reduces visual effects to speed up the interface."),
        ("6", "⚡ Set Optimized Power Plan", "Changes to High or Ultimate Performance."),
        ("7", "🛠️ Run System Maintenance (SFC & DISM)", "Checks and repairs system files."),
        ("8", "⚔️ Quick Scan (Windows Defender)", "Quick check for common threats."),
        ("9", "🔍 Full Scan (Windows Defender)", "Deep scan of the entire system (time-consuming)."),
        ("10", "🌐 Clear DNS Cache", "Resolves connection and website access issues."),
        ("11", "🔄 Reset Network Settings", "Restores network settings (requires restart)."),
        ("12", "🔋 Disable Hibernation", "Frees up disk space (removes hiberfil.sys)."),
        ("13", "🔌 Enable Hibernation", "Restores hibernation functionality."),
        ("14", "🗑️ Clear Windows Event Logs", "Clears main logs (use with caution)."),
        ("15", "⚙️ Adjust Menu Delay (MenuShowDelay)", "Speeds up context menu display."),
        ("0", "🚪 Exit", "Closes Hyper Cleaner.")
    ]

    table = Table(show_header=False, box=None, padding=(0,1,0,1))
    table.add_column("Option", style="bold cyan", width=5, justify="right")
    table.add_column("Action", style="bright_green", min_width=40)
    table.add_column("Description", style="dim", no_wrap=False, overflow="fold") # overflow to wrap text

    for key, action, description in menu_items:
        table.add_row(f"[{key}]", action, description)

    console.print(table)
    rprint("\n[bold gold1]👉 Enter the number of the desired option:[/bold gold1]")


def main():
    """Main function of the script."""
    setup_logging()
    logging.info("="*20 + " Hyper Cleaner Started " + "="*20)
    logging.info(f"Date and Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}") # More common format for logs
    logging.info(f"Python Version: {sys.version.split()[0]}") # Just the version
    logging.info(f"Platform: {sys.platform} ({os.name})")

    if os.name != 'nt':
        rprint("[bold red]❌ Error: This script is designed to run only on Windows.[/bold red]")
        logging.critical("Script executed on non-Windows platform. Exiting.")
        sys.exit(1)

    if not is_admin():
        rprint("[bold red]❌ Error: This script needs to be run with administrator privileges.[/bold red]")
        rprint("[yellow]    Please right-click the script or shortcut and select 'Run as administrator'.[/yellow]")
        logging.critical("Script not run as administrator. Exiting.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    else:
        logging.info("Script run with administrator privileges.")

    actions = {
        '1': create_restore_point,
        '2': clean_disk_cache,
        '3': optimize_memory,
        '4': optimize_startup,
        '5': optimize_visuals,
        '6': set_power_plan,
        '7': run_system_maintenance,
        '8': run_defender_quick_scan,
        '9': run_defender_full_scan,
        '10': flush_dns_cache,
        '11': reset_network_settings,
        '12': disable_hibernation,
        '13': enable_hibernation,
        '14': clear_event_logs,
        '15': set_menu_show_delay,
    }

    while True:
        display_menu()
        choice = input("> ").strip()
        logging.info(f"User selected option: '{choice}'")

        if choice in actions:
            action_func = actions[choice]
            try:
                action_func()
            except Exception as e_action: # Generic catch for unexpected errors in the action function
                rprint(f"[bold red]❌ Unexpected error executing action '{action_func.__name__}': {e_action}[/bold red]")
                logging.exception(f"Fatal error in function {action_func.__name__}")
            press_enter_to_continue()
        elif choice == '0':
            rprint("\n[bold bright_blue]✨ Hyper Cleaner finished. See you next time! ✨[/bold bright_blue]")
            logging.info("User selected exit. Closing.")
            logging.info("="*20 + " Hyper Cleaner Finished " + "="*20 + "\n")
            time.sleep(1) # Short pause for the user to read
            sys.exit(0)
        else:
            rprint("[bold red]Invalid option! Try again.[/bold red]")
            logging.warning(f"Invalid option entered: {choice}")
            time.sleep(1) # Pause to see the error message


if __name__ == "__main__":
    # Ensures the console supports colors (useful if run from a simple CMD)
    os.system('') # Activates ANSI VT100 sequence processing on Windows 10+
    main()