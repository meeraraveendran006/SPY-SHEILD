import winreg
import time
import requests
import psutil
from plyer import notification

SERVER_URL = "http://127.0.0.1:5000/api/telemetry"

# Whitelisted common applications
WHITELIST = {
    "zoom.exe", "teams.exe", "chrome.exe", "msedge.exe", 
    "discord.exe", "obs64.exe", "slack.exe", "windowscamera"
}

CAPABILITIES = {
    "Camera": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam",
    "Microphone": r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
}

HIVES = [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]

device_states = {
    "Camera": {"is_active": False, "process": "None", "start_time": None},
    "Microphone": {"is_active": False, "process": "None", "start_time": None}
}

def clean_process_name(name):
    if "#" in name:
        name = name.split("#")[-1]
    if "_" in name and "Microsoft" in name:
        name = name.split("_")[0]
    return name

def evaluate_risk(proc_name):
    """Categorizes process into Authorized or High-Risk Unverified."""
    if any(item in proc_name.lower() for item in WHITELIST):
        return "AUTHORIZED"
    return "HIGH_RISK"

def kill_process(proc_name):
    """Terminates matching process instances immediately."""
    killed = False
    clean_target = proc_name.lower().replace(".exe", "")
    for proc in psutil.process_iter(['name']):
        try:
            curr = proc.info['name'].lower()
            if clean_target in curr:
                proc.kill()
                killed = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return killed

def check_active_in_key(hive, base_path):
    try:
        with winreg.OpenKey(hive, base_path) as root_key:
            subkeys_count, _, _ = winreg.QueryInfoKey(root_key)
            for i in range(subkeys_count):
                subkey_name = winreg.EnumKey(root_key, i)
                sub_path = f"{base_path}\\{subkey_name}"
                try:
                    with winreg.OpenKey(hive, sub_path) as sub_key:
                        try:
                            val, _ = winreg.QueryValueEx(sub_key, "LastUsedTimeStop")
                            if val == 0:
                                return True, clean_process_name(subkey_name)
                        except FileNotFoundError:
                            pass

                        child_count, _, _ = winreg.QueryInfoKey(sub_key)
                        for j in range(child_count):
                            child_name = winreg.EnumKey(sub_key, j)
                            child_path = f"{sub_path}\\{child_name}"
                            try:
                                with winreg.OpenKey(hive, child_path) as child_key:
                                    val, _ = winreg.QueryValueEx(child_key, "LastUsedTimeStop")
                                    if val == 0:
                                        return True, clean_process_name(child_name)
                            except (FileNotFoundError, PermissionError):
                                continue
                except (FileNotFoundError, PermissionError):
                    continue
    except (FileNotFoundError, PermissionError):
        pass
    return False, "None"

def scan_device(capability_path):
    for hive in HIVES:
        active, proc = check_active_in_key(hive, capability_path)
        if active:
            return True, proc
    return False, "None"

def send_alert(device, process, status, risk_tier, duration):
    payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device": device,
        "process": process,
        "status": status,
        "risk_tier": risk_tier,
        "duration": duration
    }

    if status == "ACTIVE":
        title_prefix = "⚠️ HIGH RISK ALERT" if risk_tier == "HIGH_RISK" else "Spy Shield Notice"
        try:
            notification.notify(
                title=f"{title_prefix}: {device} Active",
                message=f"[{risk_tier}] Process '{process}' engaged {device.lower()}.",
                app_name="Spy Shield",
                timeout=4
            )
        except Exception:
            pass

    try:
        requests.post(SERVER_URL, json=payload, timeout=2)
    except Exception:
        pass

print("[*] Spy Shield Active. Watching camera and microphone streams...")

while True:
    for device, path in CAPABILITIES.items():
        is_active, active_proc = scan_device(path)
        last_state = device_states[device]["is_active"]

        # CASE 1: Device Opened
        if is_active and not last_state:
            risk = evaluate_risk(active_proc)
            device_states[device]["is_active"] = True
            device_states[device]["process"] = active_proc
            device_states[device]["start_time"] = time.time()
            send_alert(device, active_proc, "ACTIVE", risk, "Active now")

        # CASE 2: Device Closed
        elif not is_active and last_state:
            elapsed_sec = int(time.time() - (device_states[device]["start_time"] or time.time()))
            duration_str = f"{elapsed_sec}s" if elapsed_sec < 60 else f"{elapsed_sec // 60}m {elapsed_sec % 60}s"
            prev_proc = device_states[device]["process"]
            risk = evaluate_risk(prev_proc)

            device_states[device]["is_active"] = False
            device_states[device]["process"] = "None"
            device_states[device]["start_time"] = None
            send_alert(device, prev_proc, "IDLE", risk, duration_str)

    time.sleep(0.5)