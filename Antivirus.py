import os
import subprocess
import hashlib
import sqlite3
import concurrent.futures
import tempfile
import shutil
import webbrowser
import glob
import socket 
import re
import requests
import pyinotify
def is_file_infected_md5(md5):
    md5_connection = sqlite3.connect("MD5basedatabase.db")
    main_connection = sqlite3.connect("main.db")
    daily_connection = sqlite3.connect("daily.db")
    old_virus_base_connection = sqlite3.connect("oldvirusbase.db")
    virus_base_connection = sqlite3.connect("virusbase.db")
    full_md5_connection = sqlite3.connect("Hash.db")
    
    # Check in the MD5base table
    md5_command = md5_connection.execute("SELECT COUNT(*) FROM MD5base WHERE field1 = ?;", (md5,))
    md5_result = md5_command.fetchone()[0]
    if md5_result > 0:
        md5_connection.close()
        return True 
   # Check in the main table at field2 or field1
    main_command = main_connection.execute("SELECT COUNT(*) FROM main WHERE field2 = ? OR field1 = ?;", (md5, md5))
    main_result = main_command.fetchone()[0]
    if main_result > 0:
     main_connection.close()
     return True
       # Check in the main0 table
    main0_command = main_connection.execute("SELECT COUNT(*) FROM main0 WHERE field2 = ?;", (md5,))
    main0_result = main0_command.fetchone()[0]
    if main0_result > 0:
        main_connection.close()
        return True
     # Check in the dailyz table
    daily0_command = daily_connection.execute("SELECT COUNT(*) FROM dailyz WHERE field1 = ?;", (md5,))
    daily0_result = daily0_command.fetchone()[0]
    if daily0_result > 0:
        daily_connection.close()
        return True 
    # Check in the daily table at field2 or field1
    daily_command = daily_connection.execute("SELECT COUNT(*) FROM daily WHERE field2 = ? OR field1 = ?;", (md5, md5))
    daily_result = daily_command.fetchone()[0]
    if daily_result > 0:
     daily_connection.close()
     return True
    # Check in the targetedthreats table
    old_virus_base4_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM targetedthreats WHERE MD5 = ?;", (md5,))
    old_virus_base4_result = old_virus_base4_command.fetchone()[0]
    if old_virus_base4_result > 0:
        old_virus_base_connection.close()
        return True
       # Check in the oldmalwares table
    old_malwares_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldmalwares WHERE field1 = ?;", (md5,))
    old_malwares_result = old_malwares_command.fetchone()[0]
    if old_malwares_result > 0:
        old_virus_base_connection.close()
        return True
    # Check in the oldvirusbase table
    old_virus_base_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase WHERE field2 = ?;", (md5,))
    old_virus_base_result = old_virus_base_command.fetchone()[0]
    if old_virus_base_result > 0:
        old_virus_base_connection.close()
        return True
    # Check in the oldvirusbase2 table
    old_virus_base2_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase2 WHERE field1 = ?;", (md5,))
    old_virus_base2_result = old_virus_base2_command.fetchone()[0]
    if old_virus_base2_result > 0:
        old_virus_base_connection.close()
        return True   
    # Check in the oldvirusbase3 table
    old_virus_base3_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase3 WHERE field2 = ?;", (md5,))
    old_virus_base3_result = old_virus_base3_command.fetchone()[0]
    if old_virus_base3_result > 0:
        old_virus_base_connection.close()
        return True  
    # Check in the virusbase table
    virus_base_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase WHERE field1 = ?;", (md5,))
    virus_base_result = virus_base_command.fetchone()[0]
    if virus_base_result > 0:
        virus_base_connection.close()
        return True  
    # Check in the virusbase2 table
    virus_base2_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase2 WHERE field1 = ?;", (md5,))
    virus_base2_result = virus_base2_command.fetchone()[0]
    if virus_base2_result > 0:
        virus_base_connection.close()
        return True  
    # Check in the HashDB table
    full_md5_command = full_md5_connection.execute("SELECT COUNT(*) FROM HashDB WHERE hash = ?;", (md5,))
    full_md5_result = full_md5_command.fetchone()[0]
    if full_md5_result > 0:
        full_md5_connection.close()
        return True
    daily_connection.close()
    md5_connection.close()
    main_connection.close()
    old_virus_base_connection.close()
    virus_base_connection.close()
    full_md5_connection.close()
    return False
def is_file_infected_sha1(sha1):
    # Check in the SHA256hashes database for SHA1 hashes
    database_path_sha256_hashes = "SHA256hashes.db"
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha1_command_text = "SELECT EXISTS(SELECT 1 FROM malwarescomsha1 WHERE field1 = ? LIMIT 1);"
    sha1_result = connection_sha256_hashes.execute(sha1_command_text, (sha1,)).fetchone()

    if sha1_result and sha1_result[0]:
        connection_sha256_hashes.close()
        return True

    # If the SHA1 hash was not found in the SHA256hashes.db database,
    # Check in the abusech.db database for SHA1 hashes in SSLBL table with field2.
    database_path_abusech = "abusech.db"
    connection_abusech = sqlite3.connect(database_path_abusech)

    sslbl_command_text = "SELECT EXISTS(SELECT 1 FROM SSLBL WHERE field2 = ? LIMIT 1);"
    sslbl_result = connection_abusech.execute(sslbl_command_text, (sha1,)).fetchone()

    connection_abusech.close()

    if sslbl_result and sslbl_result[0]:
        return True
    # If the code reaches this point, it means the SHA1 hash was not found in both databases.
    return False

def is_file_infected_sha256(sha256):
    database_path_0 = "batchvirusbase.db"
    database_path_sha256 = "SHA256databasesqlite.db"
    database_path_fake_domain = "vxugfakedomain.db"
    database_path_sha256_hashes = "SHA256hashes.db"
    database_path_emotet_ioc = "IOC_Emotet.db"  # New database path
    database_path_full_sha256 = "full_sha256.db"  # New database path
    database_path_abusech = "abusech.db"  # New database path
    database_path_oldvirusbase = "oldvirusbase.db"  # New database path
     # Check in the virusign table
    connection_oldvirusbase= sqlite3.connect(database_path_oldvirusbase)
    virusign_command_text = "SELECT EXISTS(SELECT 1 FROM virusign WHERE field3 = ? LIMIT 1) FROM virusign WHERE field3 = ?;"
    virusign_result = connection_oldvirusbase.execute(virusign_command_text, (sha256, sha256)).fetchone()

    if virusign_result and virusign_result[0]:
        connection_oldvirusbase.close()
        return True
         # Check in the kicomantivirus table
    connection_oldvirusbase= sqlite3.connect(database_path_oldvirusbase)
    kicomantivirus_command_text = "SELECT EXISTS(SELECT 1 FROM kicomantivirus WHERE field4 = ? LIMIT 1) FROM kicomantivirus WHERE field4 = ?;"
    kicomantivirus_result = connection_oldvirusbase.execute(kicomantivirus_command_text, (sha256, sha256)).fetchone()

    if kicomantivirus_result and kicomantivirus_result[0]:
        connection_oldvirusbase.close()
        return True
    # Check in the virusignfull table
    connection_oldvirusbase= sqlite3.connect(database_path_oldvirusbase)
    virusignfull_command_text = "SELECT EXISTS(SELECT 1 FROM virusignfull WHERE field3 = ? LIMIT 1) FROM virusignfull WHERE field3 = ?;"
    virusignfull_result = connection_oldvirusbase.execute(virusignfull_command_text, (sha256, sha256)).fetchone()

    if virusignfull_result and virusignfull_result[0]:
        connection_oldvirusbase.close()
        return True
    # Check in the targetedthreats table
    connection_oldvirusbase= sqlite3.connect(database_path_oldvirusbase)
    targetedthreats_command_text = "SELECT EXISTS(SELECT 1 FROM targetedthreats WHERE SHA256 = ? LIMIT 1) FROM targetedthreats WHERE SHA256 = ?;"
    targetedthreats_result = connection_oldvirusbase.execute(targetedthreats_command_text, (sha256, sha256)).fetchone()

    if targetedthreats_result and targetedthreats_result[0]:
        connection_oldvirusbase.close()
        return True
      # Check in the sha256amnestytech0 table
    connection_oldvirusbase= sqlite3.connect(database_path_oldvirusbase)
    tech_command_text = "SELECT EXISTS(SELECT 1 FROM sha256amnestytech WHERE field1 = ? LIMIT 1) FROM sha256amnestytech WHERE field1 = ?;"
    tech_result = connection_oldvirusbase.execute(tech_command_text, (sha256, sha256)).fetchone()

    if tech_result and tech_result[0]:
        connection_oldvirusbase.close()
        return True
      # Check in the samplesstalkware table
    connection_oldvirusbase = sqlite3.connect(database_path_oldvirusbase)
    stalkware_command_text = "SELECT EXISTS(SELECT 1 FROM samplesstalkware WHERE SHA256 = ? LIMIT 1) FROM samplesstalkware WHERE SHA256 = ?;"
    stalkware_result = connection_oldvirusbase.execute(stalkware_command_text, (sha256, sha256)).fetchone()

    if stalkware_result and stalkware_result[0]:
        connection_oldvirusbase.close()
        return True
  # Check in the esetmalwareioc table
    connection_oldvirusbase = sqlite3.connect(database_path_oldvirusbase)

    eset_command_text = "SELECT EXISTS(SELECT 1 FROM esetmalwareioc WHERE field1 = ? LIMIT 1) FROM esetmalwareioc WHERE field1 = ?;"
    eset_result = connection_oldvirusbase.execute(eset_command_text, (sha256, sha256)).fetchone()

    if eset_result and eset_result[0]:
        connection_oldvirusbase.close()
        return True
    # Check in the SHA256 table in abusech database
    connection = sqlite3.connect(database_path_0)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection.execute(sha256_command_text, (sha256, sha256)).fetchone()

    if sha256_result and sha256_result[0]:
        connection.close()
        return True
    # Check in the abusech database full_sha256 table
    connection_abusech = sqlite3.connect(database_path_abusech)

    abusech_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field3 = ? LIMIT 1) FROM full_sha256 WHERE field3 = ?;"
    abusech_result = connection_abusech.execute(abusech_command_text, (sha256, sha256)).fetchone()

    connection_abusech.close()

    if abusech_result and abusech_result[0]:
        return True

    # Check in the full_sha256 database full_sha256 table
    connection_full_sha256 = sqlite3.connect(database_path_full_sha256)

    full_sha256_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field1 = ? LIMIT 1) FROM full_sha256 WHERE field1 = ?;"
    full_sha256_result = connection_full_sha256.execute(full_sha256_command_text, (sha256, sha256)).fetchone()

    connection_full_sha256.close()

    if full_sha256_result and full_sha256_result[0]:
        return True

    # Check in the SHA256 database
    connection_sha256 = sqlite3.connect(database_path_sha256)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection_sha256.execute(sha256_command_text, (sha256, sha256)).fetchone()

    connection_sha256.close()

    if sha256_result and sha256_result[0]:
        return True

    # Check in the vxugfakedomain database
    connection_fake_domain = sqlite3.connect(database_path_fake_domain)

    fake_domain_command_text = "SELECT EXISTS(SELECT 1 FROM vxugfakedomain WHERE field5 = ? LIMIT 1) FROM vxugfakedomain WHERE field5 = ?;"
    fake_domain_result = connection_fake_domain.execute(fake_domain_command_text, (sha256, sha256)).fetchone()

    connection_fake_domain.close()

    if fake_domain_result and fake_domain_result[0]:
        return True

    # Check in the SHA256hashes database
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha256_hashes_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256hashes WHERE field1 = ? LIMIT 1) FROM SHA256hashes WHERE field1 = ?;"
    sha256_hashes_result = connection_sha256_hashes.execute(sha256_hashes_command_text, (sha256, sha256)).fetchone()

    connection_sha256_hashes.close()

    if sha256_hashes_result and sha256_hashes_result[0]:
        return True

    # Check in the Emotet IOC database
    connection_emotet_ioc = sqlite3.connect(database_path_emotet_ioc)  # New database connection

    emotet_ioc_command_text = "SELECT EXISTS(SELECT 1 FROM IOC_Emotet WHERE field1 = ? LIMIT 1) FROM IOC_Emotet WHERE field1 = ?;"  # New table and field names
    emotet_ioc_result = connection_emotet_ioc.execute(emotet_ioc_command_text, (sha256, sha256)).fetchone()

    connection_emotet_ioc.close()

    if emotet_ioc_result and emotet_ioc_result[0]:
        return True

    # If the code reaches this point, it means the record with the specified field1 value was not found in any of the databases.
    return False

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha1(file_path):
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()
def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()
def scan_folder_with_clamscan(folder_path):
    try:
        current_folder = os.getcwd()
        clamscan_path = os.path.join(current_folder, "clamscan")
        subprocess.run([clamscan_path, "-r", "--heuristic-alerts=yes", "--remove=yes", "--detect-pua=yes", "--normalize=no", folder_path])
    except Exception as e:
        print(f"Error running ClamScan: {e}")
def delete_file(file_path):
    try:
        os.remove(file_path)
        return f"Infected file deleted: {file_path}"
    except Exception as e:
        return f"Error deleting {file_path}: {e}"

def scan_file(file_path):
    try:
        file_size = os.path.getsize(file_path)
        
        # Skip empty files
        if file_size == 0:
            return f"Clean file: {file_path}"
        
        # Calculate hash values
        md5 = calculate_md5(file_path)
        sha1 = calculate_sha1(file_path)
        sha256 = calculate_sha256(file_path)
        
        # Check if the file is infected using hash-based methods
        if is_file_infected_md5(md5) or is_file_infected_sha1(sha1) or is_file_infected_sha256(sha256):
            print(f"Infected file detected: {file_path}\nMD5 Hash: {md5}")
            print(delete_file(file_path))  # Automatically delete infected file
        else:
            return f"Clean file: {file_path}"
        
    except PermissionError:
        return f"Access denied: {file_path}"
    except Exception as e:
        return f"Error processing {file_path}: {e}"

def scan_folder_parallel(folder_path):
    infected_files = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path) for file in files]
        results = executor.map(scan_file, file_paths)
        
        for result in results:
            if result and result.startswith("Infected"):
                infected_files.append(result)
            elif result:
                print(result)

def scan_running_files_with_custom_method():
    temp_dir = tempfile.mkdtemp(prefix="running_file_scan_")

    try:
        running_files = []

        for pid in os.listdir("/proc"):
            if pid.isdigit():
                pid_dir = os.path.join("/proc", pid)
                exe_link = os.path.join(pid_dir, "exe")

                try:
                    exe_path = os.readlink(exe_link)
                    if os.path.exists(exe_path) and os.path.isfile(exe_path):
                        running_files.append(exe_path)
                except (OSError, FileNotFoundError):
                    pass

        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(scan_and_check_file, running_files, [temp_dir] * len(running_files))

        print("Custom scan finished.")

    except Exception as e:
        print(f"Error scanning running files: {e}")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def scan_and_check_file(file_path, temp_dir):
    try:
        md5 = calculate_md5(file_path)
        sha1 = calculate_sha1(file_path)
        sha256 = calculate_sha256(file_path)
        if is_file_infected_md5(md5) or is_file_infected_sha1(sha1) or is_file_infected_sha256(sha256):
            print(f"Infected file detected: {file_path}")
            print(delete_file(file_path))  # Automatically delete infected file 
        else:
            print(f"Clean file: {file_path}")
        
        shutil.copy2(file_path, temp_dir)
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")

def scan_running_files_with_custom_and_clamav_continuous():
    try:
        while True:
            # Create a ThreadPoolExecutor to run ClamAV and custom scans concurrently
            with concurrent.futures.ThreadPoolExecutor() as executor:
                clamav_scan = executor.submit(scan_running_files_with_clamav)
                custom_scan = executor.submit(scan_running_files_with_custom_method)
                clamonacc_scan = executor.submit(scan_running_files_with_clamav)
                # Wait for both scans to complete
                clamav_scan.result()
                custom_scan.result()
                clamonacc_scan.result()

            print("Waiting for the next combined scan...")

    except KeyboardInterrupt:
        print("\nContinuous combined scan stopped.")

def scan_running_files_with_clamav():
    # Create a temporary directory to store copies of running files
    temp_dir = tempfile.mkdtemp(prefix="running_file_scan_")

    try:
        # Iterate through the /proc directory to find running process IDs
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                pid_dir = os.path.join("/proc", pid)
                exe_link = os.path.join(pid_dir, "exe")
                
                try:
                    # Resolve symbolic link to get the path of the running file
                    exe_path = os.readlink(exe_link)
                    if os.path.exists(exe_path) and os.path.isfile(exe_path):
                        # Copy the running file to the temporary directory for scanning
                        shutil.copy2(exe_path, temp_dir)
                except (OSError, FileNotFoundError):
                    # Some processes may have restricted permissions, skip them
                    pass

        # Perform a ClamAV scan on the copied running files
        clamscan_path = shutil.which("clamscan")
        if clamscan_path:
            print("Scanning running files with ClamAV...")
            subprocess.run([clamscan_path, "-r", temp_dir])
        else:
            print("ClamAV not found, skippiget_running_firefox_urlsng running file scan.")

    except Exception as e:
        print(f"Error scanning running files: {e}")

    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)
def is_website_infected(url):
    databases = ['viruswebsites.db', 'viruswebsite.db', 'viruswebsitesbig.db', 'virusip.db', 'viruswebsitessmall.db','abusech.db','oldvirusbase.db']
    formatted_url = format_url(url)  # Format the URL
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0 and format_url
    zero_url = "0.0.0.0" # URL with 0.0.0.0 prefixed

    for database in databases:
        conn = sqlite3.connect(database)
        cursor = conn.cursor()

        queries = [
             "SELECT * FROM targetedthreatsurl WHERE ioc = ?",
            "SELECT * FROM ipsamnestytech WHERE field1 = ?",
            "SELECT * FROM hostsstalkware WHERE field1 = ?",
            "SELECT * FROM networkstalkware WHERE indicator = ?",
            "SELECT * FROM domainsamnestytech WHERE field1 = ?",
            "SELECT * FROM viruswebsites WHERE field1 = ?",
            "SELECT * FROM viruswebsite WHERE field1 = ?",
            "SELECT * FROM inactive WHERE field1 = ?",
            "SELECT * FROM malwarebazaar WHERE field1 = ?",
            "SELECT * FROM ultimatehostblacklist WHERE field2 = ?",
            "SELECT * FROM continue WHERE field1 = ?",
            "SELECT * FROM virusip WHERE field1 = ?"
            "SELECT * FROM mcafee WHERE field1 = ?",
            "SELECT * FROM full_urls WHERE field3 = ?",
            "SELECT * FROM full_domains WHERE field3 = ?",
            "SELECT * FROM paloaltofirewall WHERE field1 = ?",
            "SELECT * FROM SSBLIP WHERE field2 = ?",
            "SELECT * FROM \"full_ip-port\" WHERE field3 = ?"
        ]

        for query in queries:
            try:
                result = cursor.execute(query, (formatted_url,)).fetchone()
                if result:
                    cursor.close()
                    conn.close()
                    return True

                result_ip = cursor.execute(query, (ip_prefixed_url,)).fetchone()
                if result_ip:
                    cursor.close()
                    conn.close()
                    return True

                result_zero = cursor.execute(query, (zero_url,)).fetchone()
                if result_zero:
                    cursor.close()
                    conn.close()
                    return True
            except sqlite3.OperationalError:
                pass  # Table is not found, ignore it.

        cursor.close()
        conn.close()

def format_url(url):
    if url:
        formatted_url = url.strip().lower()
        if formatted_url.startswith("https://"):
            formatted_url = formatted_url.replace("https://", "")
        elif formatted_url.startswith("http://"):
            formatted_url = formatted_url.replace("http://", "")
        if formatted_url.startswith("www."):
            formatted_url = formatted_url.replace("www.", "")
        formatted_url = formatted_url.split('/')[0]
        return formatted_url
def get_running_ips():
    try:
        netstat_output = subprocess.run(["netstat", "-tn"], capture_output=True, text=True)
        lines = netstat_output.stdout.split("\n")[2:]  # Skip the first two lines
        running_ips = set()

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ip_port = parts[4]
                ip_port_parts = ip_port.split(":")
                if len(ip_port_parts) == 2:
                    ip, port = ip_port_parts
                    running_ips.add(ip)
                    running_ips.add(f"{ip}:{port}")

        return list(running_ips)
    except Exception as e:
        print(f"Hata: {e}")
        return []
def real_time_web_protection():
    infected_ips = []
    while True:
        running_ips = get_running_ips()
        
        for ip in running_ips:
            if is_website_infected(ip):
                print(f"The IP address {ip} is infected.")
                infected_ips.append(ip)
                disconnect_ip(ip)
                open_webguard_page()
            else:
                print(f"The IP address {ip} is clean.")
        return infected_ips
def disconnect_ip(ip):
    try:
        # For example, a command that can be used to block the IP address on Linux
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        print(f"Disconnected IP address: {ip}")
    except Exception as e:
        print(f"Error disconnecting IP address {ip}: {e}")
def open_webguard_page():
    # Path to current directory
    current_directory = os.getcwd()

    # WebGuard.html path
    webguard_path = os.path.join(current_directory, 'WebGuard.html')

    # Open WebGuard.html with Firefox
    webbrowser.get('firefox').open('file://' + webguard_path)
def find_firefox_profile(default_esr=False):
    try:
        # Get the user's home directory        
        home_dir = os.path.expanduser("~")

        # Use glob to find Firefox profile folder
        profile_paths = glob.glob(os.path.join(home_dir, ".mozilla/firefox/*default"))
        
        if default_esr:
            profile_paths = glob.glob(os.path.join(home_dir, ".mozilla/firefox/*default-esr"))

        if profile_paths:
            return profile_paths[0]
        else:
            return None
    except Exception as e:
        print(f"Error finding Firefox profile: {e}")
        return None
def extract_ip_from_url(url):
    try:
        hostname = url.split('/')[2]  # Extract hostname from URL
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        print(f"Error extracting IP from URL {url}: {e}")
        return None
def run_clamonacc_with_remove():
    try:
        # When running the clamonacc command in clamav call it using the "--remove" argument
        subprocess.run(["clamonacc", "--remove"], check=True)
        print("clamonacc successfully executed with --remove argument.")
    except subprocess.CalledProcessError as e:
        print("Error executing clamonacc:", e)
def is_website_infected0(content):
    databases = ['viruswebsites.db', 'viruswebsite.db', 'viruswebsitesbig.db', 'virusip.db', 'viruswebsitessmall.db','abusech.db','oldvirusbase.db']
    formatted_url = format_url(content)  # Format URL
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0 and format_url
    zero_url = "0.0.0.0" # URL with 0.0.0.0 prefixed

    for database in databases:
        conn = sqlite3.connect(database)
        cursor = conn.cursor()

        queries = [
             "SELECT * FROM targetedthreatsurl WHERE ioc = ?",
            "SELECT * FROM ipsamnestytech WHERE field1 = ?",
            "SELECT * FROM hostsstalkware WHERE field1 = ?",
            "SELECT * FROM networkstalkware WHERE indicator = ?",
            "SELECT * FROM domainsamnestytech WHERE field1 = ?",
            "SELECT * FROM viruswebsites WHERE field1 = ?",
            "SELECT * FROM viruswebsite WHERE field1 = ?",
            "SELECT * FROM inactive WHERE field1 = ?",
            "SELECT * FROM malwarebazaar WHERE field1 = ?",
            "SELECT * FROM ultimatehostblacklist WHERE field2 = ?",
            "SELECT * FROM continue WHERE field1 = ?",
            "SELECT * FROM virusip WHERE field1 = ?"
            "SELECT * FROM mcafee WHERE field1 = ?",
            "SELECT * FROM full_urls WHERE field3 = ?",
            "SELECT * FROM full_domains WHERE field3 = ?",
            "SELECT * FROM paloaltofirewall WHERE field1 = ?",
            "SELECT * FROM SSBLIP WHERE field2 = ?",
            "SELECT * FROM \"full_ip-port\" WHERE field3 = ?"
        ]

        for query in queries:
            try:
                result = cursor.execute(query, (formatted_url,)).fetchone()
                if result:
                    cursor.close()
                    conn.close()
                    return True

                result_ip = cursor.execute(query, (ip_prefixed_url,)).fetchone()
                if result_ip:
                    cursor.close()
                    conn.close()
                    return True

                result_zero = cursor.execute(query, (zero_url,)).fetchone()
                if result_zero:
                    cursor.close()
                    conn.close()
                    return True
            except sqlite3.OperationalError:
                pass  # Ignore the table is not found error.

        cursor.close()
        conn.close()
# Run command to download firejail
firejail_install_command = "sudo apt install firejail -y"
auditd_install_command = "sudo apt install  auditd  -y"
subprocess.run(firejail_install_command, shell=True)
subprocess.run(auditd_install_command , shell=True)
def access_firefox_history_continuous():
    try:
        # Find the Firefox profile folder

        profile_path = find_firefox_profile()

        if profile_path is None:
            print("Firefox profile not found.")
            return

        # Create the path to the Firefox history database
        firefox_db_path = os.path.join(profile_path, "places.sqlite")

        if not os.path.exists(firefox_db_path):
            # If the database doesn't exist in the default folder, try default-esr folder
            profile_path_esr = find_firefox_profile(default_esr=True)
            if profile_path_esr:
                firefox_db_path = os.path.join(profile_path_esr, "places.sqlite")
            else:
                print("Firefox history database not found.")
                return

        last_visited_websites = []  # To keep track of the last visited websites

        while True:
            # Copy the Firefox history database to a temporary folder
            temp_dir = tempfile.mkdtemp(prefix="firefox_history_")
            copied_db_path = os.path.join(temp_dir, "places.sqlite")
            shutil.copy2(firefox_db_path, copied_db_path)

            # Connect with the copied database
            connection = sqlite3.connect(copied_db_path)
            cursor = connection.cursor()

            # Get visited sites with query
            query = "SELECT title, url FROM moz_places ORDER BY id DESC LIMIT 5;"
            cursor.execute(query)
            results = cursor.fetchall()

           # Scan visited websites and show results
            for row in results:
                title, url = row
                print(f"Scanning URL: {url}")
                if is_website_infected(url):
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"The website is infected: {url}")
                        print(f"Infected IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the infected IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_webguard_page()  # Open the webguard.html file
                else:
                    print(f"The website is clean: {url}")

                if len(last_visited_websites) >= 5:
                    last_visited_websites.pop(0)  # Remove the oldest visited website
                last_visited_websites.append(url)
            # Close the connection and clean the temporary folder

            connection.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        print(f"Error accessing Firefox history: {e}")
def access_firefox_history_continuous0(file_path):
    try:
        # Find the Firefox profile folder

        profile_path = find_firefox_profile()

        if profile_path is None:
            print("Firefox profile not found.")
            return

        # Create the path to the Firefox history database
        firefox_db_path = os.path.join(profile_path, "places.sqlite")

        if not os.path.exists(firefox_db_path):
            # If the database doesn't exist in the default folder, try default-esr folder
            profile_path_esr = find_firefox_profile(default_esr=True)
            if profile_path_esr:
                firefox_db_path = os.path.join(profile_path_esr, "places.sqlite")
            else:
                print("Firefox history database not found.")
                return

        last_visited_websites = []  # To keep track of the last visited websites

        while True:
            # Copy the Firefox history and access_firefox_history_continuous0 database to a temporary folder
            temp_dir = tempfile.mkdtemp(prefix="firefox_history_")
            copied_db_path = os.path.join(temp_dir, "places.sqlite")
            shutil.copy2(firefox_db_path, copied_db_path)

            # Connect with the copied database
            connection = sqlite3.connect(copied_db_path)
            cursor = connection.cursor()

            # Get visited sites with query
            query = "SELECT title, url FROM moz_places ORDER BY id DESC LIMIT 5;"
            cursor.execute(query)
            results = cursor.fetchall()

           # Scan visited sites and show results
            for row in results:
                title, url = row
                print(f"Scanning URL: {url}")
                if is_website_infected(url):
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"The website is infected: {url}")
                        print(f"Infected IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the infected IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_webguard_page()  # Open the webguard.html file
                            delete_file(file_path)
                else:
                    print(f"The website is clean: {url}")

                if len(last_visited_websites) >= 5:
                    last_visited_websites.pop(0)  # Remove the oldest visited website
                last_visited_websites.append(url)
            # Close the connection and clean the temporary folder
            connection.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        print(f"Error accessing Firefox history: {e}")
def scan_file_for_malicious_content(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except Exception as e:
        return "Error reading file " + file_path + ": " + str(e)

    if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
        print( "Excluded IP/Host: " + file_path)

    if is_website_infected0(content) or is_website_infected0("www." + format_url(content)):
        print("Infected file (Malicious Website Content): " + file_path)
        delete_file(file_path)  # Remove the infected file
    else:
        print("Clean file according to malicious content check:" + file_path )
    sandbox_command = f"firejail --noprofile python {file_path}"

    try:
        result = subprocess.run(sandbox_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sandbox_output = result.stdout.decode('utf-8')
        
        if re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0', sandbox_output, re.IGNORECASE):
            print("Excluded IP/Host found in sandbox output")
        
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', sandbox_output)
        for url in urls:
            response = requests.get(url)
            if is_website_infected(response.content):
                print("Infected website found in sandbox output")
                delete_file(file_path)
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sandbox_output)
        for ip in ip_addresses:
            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"IP Address: {ip}, Hostname: {hostname[0]}")
            except socket.herror:
                print(f"IP Address: {ip}, Hostname: Not found")

    except subprocess.CalledProcessError as e:
        print("Error running sandbox:", e)
def scan_file_for_malicious_content_without_sandbox(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except Exception as e:
        return "Error reading file " + file_path + ": " + str(e)

    if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
        print ("Excluded IP/Host: " + file_path)

    if is_website_infected0(content) or is_website_infected0("www." + format_url(content)):
        print("Infected file (Malicious Website Content): " + file_path)
        delete_file(file_path)  # Remove the infected file

    return "Clean file according to malware content check: " + file_path
def scan_running_files_with_custom_method0():
    running_files = []

    for pid in os.listdir("/proc"):
        if pid.isdigit():
            pid_dir = os.path.join("/proc", pid)
            exe_link = os.path.join(pid_dir, "exe")

            try:
                exe_path = os.readlink(exe_link)
                if os.path.exists(exe_path) and os.path.isfile(exe_path):
                    running_files.append(exe_path)
            except (OSError, FileNotFoundError):
                pass

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = executor.map(scan_file_for_malicious_content_without_sandbox, running_files)

    print("Scanning running files finished.")
    
    for result in results:
        print(result)
def scan_folder_with_malware_content_check(folder_path):
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        content = file.read()
                except Exception as e:
                    print("Error reading file", file_path, ":", e)
                    continue

                if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
                    print("Excluded IP/Host:", file_path)
                    continue

                if is_website_infected0(content) or is_website_infected0(format_url(content)):
                    print("Infected file (Malicious Website Content):", file_path)
                    delete_file(file_path)
                # Add more conditions to check for different types of content

                # You can include additional checks here based on your requirements

                print("Clean file according to malware content check :", file_path)
def real_time_web_protection0(file_path):
    infected_ips = []
    while True:
        running_ips = get_running_ips()
        
        for ip in running_ips:
            if is_website_infected(ip):
                print(f"The IP address {ip} is infected.")
                infected_ips.append(ip)
                disconnect_ip(ip)
                open_webguard_page()
                delete_file(file_path)
            else:
                print(f"The IP address {ip} is clean.")
        return infected_ips

def calculate_hashes_in_folder(folder_path):
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        print(f"Calculating hashes for files in {folder_path}")
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                print(f"Calculating hashes for {file_path}")
                md5_hash = calculate_md5(file_path)
                sha1_hash = calculate_sha1(file_path)
                sha256_hash = calculate_sha256(file_path)
                print(f"File: {file_path}")
                print(f"MD5 Hash: {md5_hash}")
                print(f"SHA-1 Hash: {sha1_hash}")
                print(f"SHA-256 Hash: {sha256_hash}")
                print("-" * 40)
    else:
        print("Invalid folder path.")
# Get the current username
current_username = os.getlogin()

directories_to_monitor = [
    f"/home/{current_username}"
]

class FileChangeHandler(pyinotify.ProcessEvent):
    def __init__(self, suspicious_file_path):
        self.suspicious_file_path = suspicious_file_path
        self.suspicious_file_hash = self.calculate_file_hash(suspicious_file_path)
        super().__init__()

    def process_IN_CLOSE_WRITE(self, event):
        if not event.dir:
            file_path = event.pathname
            original_extension = os.path.splitext(self.suspicious_file_path)[1]
            new_extension = os.path.splitext(file_path)[1]

            if original_extension != new_extension:
                print(f"File extension has changed: {self.suspicious_file_path} -> {file_path}")
                new_file_hash = self.calculate_file_hash(file_path)

                if new_file_hash != self.suspicious_file_hash:
                    print(f"File content has changed: {self.suspicious_file_path} -> {file_path}")
                    delete_file(self.suspicious_file_path)  # Delete suspicious file
            else:
                self.handle_file_change(file_path)

    def handle_file_change(self, file_path):
        try:
            # Attempt to read the file as UTF-8
            with open(file_path, 'r', encoding='utf-8') as file:
                file.read()
        except UnicodeDecodeError:
            # File is not readable as UTF-8 (potentially encrypted)
            print(f"File is not readable as UTF-8: {file_path}")
            delete_file(self.suspicious_file_path)  # Delete suspicious file

    def calculate_file_hash(self, file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"Deleted file: {file_path}")
    except Exception as e:
        print(f"Error deleting file: {file_path} - {e}")

def start_monitoring(suspicious_file_path, file_path):
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_CLOSE_WRITE

    event_handler = FileChangeHandler(suspicious_file_path)
    event_handler.file_path = file_path
    notifier = pyinotify.Notifier(wm, event_handler)

    for directory in directories_to_monitor:
        wm.add_watch(directory, mask, rec=True)

    print("File change monitor started.")

    try:
        notifier.loop()
    except KeyboardInterrupt:
        notifier.stop()
def main():
    while True:
        print("Please run program as a root") 
        print("Select an option:")
        print("1. Perform a file scan")
        print("2. Enable real-time protection (scan running files with ClamAV)")
        print("3. Check if a website is infected by typing the URL")
        print("4. Real-time web protection")
        print("5. Real-time web and file protection")
        print("6. Perform intuitive  sandbox file scan (Run on vm and do perform a file scan first)")
        print("7. Calculate hashes of files in a folder")
        print("8. Exit")
        
        choice = input("Enter your choice: ")
        if choice == "1":
            folder_path = input("Enter the path of the folder to scan: ")

            if os.path.exists(folder_path) and os.path.isdir(folder_path):
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                    executor.submit(scan_folder_with_clamscan, folder_path)
                    executor.submit(scan_folder_parallel, folder_path)
                    executor.submit(scan_folder_with_malware_content_check, folder_path)
            else:
                print("Invalid folder path.")
        elif choice == "2":
            scan_running_files_with_custom_and_clamav_continuous()

        elif choice == "3":
            website_url = input("Enter the website URL to check: ")
            if is_website_infected(website_url):
                print("The website is infected.")
            else:
                print("The website is clean.")

        elif choice == "4":
            # Start two functions in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                executor.submit(real_time_web_protection)
                executor.submit(access_firefox_history_continuous)
        
        elif choice == "5":
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                executor.submit(real_time_web_protection)
                executor.submit(access_firefox_history_continuous)
                executor.submit(scan_running_files_with_custom_method)
                executor.submit(scan_running_files_with_custom_method0)
        elif choice == "6":
            file_path = input("Enter the path of the file to intuitively scan: ")
            suspicious_file_path = input("Enter the path of potential ransomware file: ")
            #  Start two functions in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future4 = executor.submit(start_monitoring, suspicious_file_path,file_path)
                future1 = executor.submit(access_firefox_history_continuous0, file_path)
                future2 = executor.submit(scan_file_for_malicious_content, file_path)
                future3 = executor.submit(real_time_web_protection0, file_path)
                # Wait for both functions to complete
                concurrent.futures.wait([future4,future1, future2,future3])
                
                # Get the results from the futures (if needed)
                result1 = future1.result()
                result2 = future2.result()
                result3 = future3.result()
                result4 = future4.result()
                # Print or handle results as needed
                print("scan_file_for_ransomware result:", result4)
                print("access_firefox_history_continuous0 result:", result1)
                print("scan_file_for_malicious_content result:", result2)
                print("scan_file_for_malicious_ip result:", result3)
        elif choice == "7":
            folder_path = input("Enter the path of the folder to calculate hashes for: ")
            calculate_hashes_in_folder(folder_path)
        elif choice == "8":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select a valid option.")
if __name__ == "__main__":
    main()