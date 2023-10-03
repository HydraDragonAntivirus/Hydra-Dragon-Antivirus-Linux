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
import curses
import tlsh 
import ssdeep
import appdirs
import getpass 
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import threading
def calculate_tlsh(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
        tlsh_value = tlsh.hash(file_data)
    return tlsh_value
def calculate_ssdeep(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            ssdeep_value = ssdeep.hash(file_data)
        return ssdeep_value
    except ImportError:
        print("The 'ssdeep' module is not installed. Please install it to calculate ssdeep hashes.")
        return None
def is_file_infected_ssdeep(file_path, similarity_threshold=0.8):
    # Calculate SSDeep for the input file
    ssdeep_value = calculate_ssdeep(file_path)

    # Connect to the daily and oldvirusbase databases
    daily_connection = sqlite3.connect("daily.db")
    oldvirusbase_connection = sqlite3.connect("oldvirusbase.db")

    try:
        # Create cursors to execute SQL queries
        daily_cursor = daily_connection.cursor()
        oldvirusbase_cursor = oldvirusbase_connection.cursor()

        # Retrieve SSDeep hashes from dailyfuzzyhashes table
        daily_cursor.execute("SELECT field4 FROM dailyfuzzyhashes;")
        for record in daily_cursor.fetchall():
            db_ssdeep = record[0]

            # Compare SSDeep hashes and check for similarity based on the provided threshold
            if ssdeep_value == db_ssdeep or ssdeep.compare(ssdeep_value, db_ssdeep) >= similarity_threshold:
                return True

        # Retrieve SSDeep hashes from virusignfull table
        oldvirusbase_cursor.execute("SELECT field1 FROM virusignfull;")
        for record in oldvirusbase_cursor.fetchall():
            db_ssdeep = record[0]

            # Compare SSDeep hashes and check for similarity based on the provided threshold
            if ssdeep_value == db_ssdeep or ssdeep.compare(ssdeep_value, db_ssdeep) >= similarity_threshold:
                return True

        # Retrieve SSDeep hashes from virusign table
        oldvirusbase_cursor.execute("SELECT field1 FROM virusign;")
        for record in oldvirusbase_cursor.fetchall():
            db_ssdeep = record[0]

            # Compare SSDeep hashes and check for similarity based on the provided threshold
            if ssdeep_value == db_ssdeep or ssdeep.compare(ssdeep_value, db_ssdeep) >= similarity_threshold:
                return True

    except Exception as e:
        print("Error:", str(e))
    finally:
        # Close the cursors and the database connections
        daily_cursor.close()
        oldvirusbase_cursor.close()
        daily_connection.close()
        oldvirusbase_connection.close()

    return False
def is_file_infected_tlsh(tlsh_value, similarity_threshold=0.8):
    # Connect to the daily database
    daily_connection = sqlite3.connect("daily.db")
    try:
        # Create a cursor to execute SQL queries
        daily_cursor = daily_connection.cursor()

        # Retrieve TLSH hashes from the malwarebazaarfuzzyhashes table
        daily_cursor.execute("SELECT field14 FROM malwarebazaarfuzzyhashes;")

        # Compare the TLSH hashes and check for similarity
        for record in daily_cursor.fetchall():
            db_tlsh = record[0]

            # Compare TLSH hashes and check for similarity based on the provided threshold
            if db_tlsh == tlsh_value:
                return True

    except Exception as e:
        print("Error:", str(e))
    finally:
        # Close the cursor and the database connection
        daily_cursor.close()
        daily_connection.close()

    return False
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
       # Check in the main0 table at field4
    main1_command = main_connection.execute("SELECT COUNT(*) FROM main0 WHERE field4 = ?;", (md5,))
    main1_result = main1_command.fetchone()[0]
    if main1_result > 0:
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
    # Check in the securiteinfo table at field1
    dailyx_command = daily_connection.execute("SELECT COUNT(*) FROM securiteinfo WHERE field1 = ? OR field1 = ?;", (md5, md5))
    dailyx_result = dailyx_command.fetchone()[0]
    if dailyx_result > 0:
     daily_connection.close()
     return True
    # Check in the others table at field1
    dailyo_command = daily_connection.execute("SELECT COUNT(*) FROM others WHERE field1 = ? OR field1 = ?;", (md5, md5))
    dailyo_result = dailyo_command.fetchone()[0]
    if dailyo_result > 0:
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
 # Check in the SHA256hashes database for SHA1 hashes in malshare
    malshare_sha1_command_text = "SELECT EXISTS(SELECT 1 FROM malsharesha1 WHERE field1 = ? LIMIT 1);"
    malshare_sha1_result = connection_sha256_hashes.execute(malshare_sha1_command_text, (sha1,)).fetchone()

    if malshare_sha1_result and malshare_sha1_result[0]:
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
    database_path_full_sha256 = "daily.db"  # New database path
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

    # Check in the daily database malwarebazaarfuzzyhashes table
    connection_full_sha256 = sqlite3.connect(database_path_full_sha256)

    full_sha256_command_text = "SELECT EXISTS(SELECT 1 FROM malwarebazaarfuzzyhashes WHERE field2 = ? LIMIT 1) FROM malwarebazaarfuzzyhashes WHERE field2 = ?;"
    full_sha256_result = connection_full_sha256.execute(full_sha256_command_text, (sha256, sha256)).fetchone()

    connection_full_sha256.close()

    if full_sha256_result and full_sha256_result[0]:
        return True

    # Check in the daily database malshare table
    connection_full_sha256 = sqlite3.connect(database_path_full_sha256)

    full_sha256x_command_text = "SELECT EXISTS(SELECT 1 FROM malshare WHERE sha256 = ? LIMIT 1) FROM malshare WHERE sha256 = ?;"
    full_sha256x_result = connection_full_sha256.execute(full_sha256x_command_text, (sha256, sha256)).fetchone()

    connection_full_sha256.close()

    if full_sha256x_result and full_sha256x_result[0]:
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
        subprocess.run(["clamscan","-r", "--heuristic-alerts=yes", "--remove=yes", "--detect-pua=yes", "--normalize=no", folder_path])
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
        ssdeep = calculate_ssdeep(file_path)
        tlsh = calculate_tlsh(file_path)
        # Check if the file is infected using hash-based methods
        if is_file_infected_md5(md5) or is_file_infected_sha1(sha1) or is_file_infected_sha256(sha256) or is_file_infected_ssdeep(ssdeep) or is_file_infected_tlsh(tlsh):
            print(f"Infected file detected: {file_path}\nMD5 Hash: {md5}")
            print(delete_file(file_path))  # Automatically delete infected file
        else:
            return f"Clean file according to databases: {file_path}"
        
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
    while True:
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
                scan_results = list(executor.map(scan_and_check_file, running_files, [temp_dir] * len(running_files)))
                malicious_results = list(executor.map(scan_file_for_malicious_content_without_sandbox, running_files))

            print("Custom scan finished.")

            # Print the results
            print("Custom Scan Results:")
            for result in scan_results:
                print(result)

            print("Malicious Content Check Results:")
            for result in malicious_results:
                print(result)

        except Exception as e:
            print(f"Error scanning running files: {e}")
def scan_and_check_file(file_path, temp_dir):
    try:
        file_size = os.path.getsize(file_path)
        
        # Skip empty files
        if file_size == 0:
            return f"Clean file: {file_path}"
        md5 = calculate_md5(file_path)
        sha1 = calculate_sha1(file_path)
        sha256 = calculate_sha256(file_path)
        ssdeep = calculate_ssdeep(file_path)
        tlsh = calculate_tlsh(file_path)
        if is_file_infected_md5(md5) or is_file_infected_sha1(sha1) or is_file_infected_sha256(sha256) or is_file_infected_ssdeep(ssdeep) or is_file_infected_tlsh(tlsh):
            print(f"Infected file detected: {file_path}")
            print(delete_file(file_path))  # Automatically delete infected file 
        else:
            print(f"Clean file according to databases: {file_path}")
        
        shutil.copy2(file_path, temp_dir)
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
def scan_running_files_in_proc():
 while True:
    try:
        malicious_results = []

        for pid in os.listdir("/proc"):
            if pid.isdigit():
                pid_dir = os.path.join("/proc", pid)
                exe_link = os.path.join(pid_dir, "exe")

                try:
                    file_path = os.readlink(exe_link)
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        try:
                            with open(file_path, "r", encoding="utf-8") as file:
                                content = file.read()
                            if re.search(r'fdisk /dev/sd[a-z]', content):
                             malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content Disk Overwriter): " + file_path)
                            if re.search(r'dd if=/dev/zero of=/dev/sd[a-z]', content):                            
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content dd Disk Overwriter): " + file_path)
                            if re.search(r'rm\s+-rf /', content):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - rm -rf /): " + file_path)
                            if re.search(r'chown /', content):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - chown /): " + file_path)
                            if re.search(r'chmod -R ugo-rwx /', content):                                
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - chmod -R ugo-rwx /): " + file_path)
                            if re.search(r'chattr\s+-R\s+\+i\s+/', content):                                
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content -  chattr -R +i /): " + file_path)
                            if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
                                malicious_results.append("Excluded IP/Host: " + file_path)
                            if is_website_infected0(content) or is_website_infected0("www." + format_url(content)) or is_website_infected0(format_url(content)):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Website Or IP Content): " + file_path)
                            if is_phishing_website0(content) or is_phishing_website0("www." + format_url(content)) or is_phishing_website0(format_url(content)):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Phishing file (Phishing Website Or IP Content): " + file_path)
                            if re.search(r'mkfs\.ext4', content):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - mkfs.ext4): " + file_path)
                            if re.search(r'ufw\s+disable', content):
                                 malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content ufw disable): " + file_path)
                            if re.search(r'shutdown', content):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - shutdown): " + file_path)
                            if re.search(r'chmod 777 /', content):
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            print("Infected file (Malicious Content - chmod 777 /): " + file_path)
                            if re.search(r'nc -l -p 4444 -e /bin/bash', content) or re.search(r'ncat -l -p 4444 -e /bin/bash', content):
                                print("Infected file (Malicious Content - Reverse Shell): " + file_path)
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'init 0', content):
                                print("Infected file (Malicious Content - init 0): " + file_path)
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'init 6', content):
                                print("Infected file (Malicious Content - init 6): " + file_path)
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};', content):
                               print("Infected file (Malicious Content - Fork Bomb): " + file_path)        
                               malicious_results.append(delete_file(file_path))  # Remove the infected file                          
                            if re.search(r'wget\s+https://', content) and re.search(r'\s+-O\s+\w+\.\w+', content):
                               print("Infected file (Malicious Content - wget with -O): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'mkfifo\s+/tmp/backpipe;\s+/bin/sh\s+0</tmp/backpipe\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+1>/tmp/backpipe', content):
                               print("Infected file (Malicious Content - FIFO Pipe and Netcat): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'mkfifo\s+/tmp/fifo;\s+cat\s+/tmp/fifo\s+\|\s+/bin/sh\s+-i\s+2>&1\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+>\s+/tmp/fifo', content):
                               print("Infected file (Malicious Content - FIFO Pipe, Shell, and Netcat): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'openssl\s+enc\s+-aes-256-cbc', content):
                               print("Infected file (Malicious (Ransomware) Content - openssl enc): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'cat\s+>\s+/dev/sda', content):
                               print("Infected file (Malicious Content - cat > /dev/sda): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'mv\s+/bin/bash\s+/bin/bash\.bak', content):
                               print("Infected file (Malicious Content - Disable Bash): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'find\s+/\s+-name\s+"*.log"', content):
                               print("Infected file (Malicious Content - Find log files): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'-exec\s+rm\s+-f\s+{}\s+;', content):
                               print("Infected file (Malicious Content - Remove log files): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'rm\s+-f\s+/lib/libc\.so\.6', content):
                               print("Infected file (Malicious Content - Remove libc.so.6): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'mkfifo\s+/\w+/\w+;\s+\S+\s+/\w+/\w+\s+\|\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+', content):
                               print("Infected file (Malicious Content - FIFO): " + file_path)
                               malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'\S+\s+\|\s+\S+', content):
                                print("Infected file (Malicious Content - Pipe): " + file_path)
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                            if re.search(r'\S+\s+/bin/sh\s+-i', content):
                                print("Infected file (Malicious Content - Shell): " + file_path)
                                malicious_results.append(delete_file(file_path))  # Remove the infected file
                        except Exception as e:
                            malicious_results.append("Error reading file " + file_path + ": " + str(e))

                except (OSError, FileNotFoundError):
                    pass

        if malicious_results:
            print("Malicious Content Results:")
            for result in malicious_results:
                print(result)
        else:
            print("No malicious content found in running files.")

    except Exception as e:
        print(f"Error scanning running files in /proc: {e}")
def scan_running_files_with_custom_and_clamav_continuous():
    try:
        while True:
            # Create a ThreadPoolExecutor to run ClamAV and custom scans concurrently
            with concurrent.futures.ThreadPoolExecutor() as executor:
                clamav_scan = executor.submit(scan_running_files_with_clamav)
                custom_scan = executor.submit(scan_running_files_with_custom_method)
                clamonacc_scan = executor.submit(run_clamonacc_with_remove)
                malicious_content_scan = executor.submit (scan_running_files_in_proc)
                # Wait for both scans to complete
                clamav_scan.result()
                custom_scan.result()
                clamonacc_scan.result()
                malicious_content_scan.result()

            print("Waiting for the next combined scan...")

    except KeyboardInterrupt:
        print("\nContinuous combined scan stopped.")
def scan_running_files_with_clamav():
 while True:
    # Create a temporary directory to store copies of running files
    temp_dir = tempfile.mkdtemp(prefix="running_file_scan_")

    try:
        # Check if ClamAV is installed and available in the system
        clamav_installed = shutil.which("clamscan")
        if clamav_installed:
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
            if os.listdir(temp_dir):
                print("Scanning running files with ClamAV...")
                subprocess.run(["clamscan", "-r", temp_dir])
            else:
                print("No running files found for scanning.")

        else:
            print("ClamAV not found, skipping running file scan.")

    except Exception as e:
        print(f"Error scanning running files: {e}")

    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)
checked_websites = set()  # Set to store checked websites
# Define a function to display a warning
def display_warning(website):
    print(f"Warning: Website '{website}' has already been checked.")
def is_phishing_website(url):
    # Format the URL
    formatted_url = format_url(url)
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0
    zero_url = "0.0.0.0"  # URL with 0.0.0.0 prefix

    # Database and table information
    db_path = 'viruswebsites.db'
    table_name = 'allphishingdomainsandlinks'
    field_name = 'field1'  # Assuming 'field1' is the field containing the URLs
    is_phishing_field = 'is_phishing_website'  # Assuming 'is_phishing_website' is the field indicating phishing

    # SQL queries to check if the URL is a phishing website
    queries = [
        f"SELECT * FROM {table_name} WHERE {field_name} = ? AND {is_phishing_field} = 1",
        f"SELECT * FROM {table_name} WHERE {field_name} = ?",
    ]

    for query in queries:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            result = cursor.execute(query, (formatted_url,)).fetchone()

            if result:
                cursor.close()
                conn.close()
                return True

            # Check ip_prefixed_url and zero_url for phishing
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
        finally:
            cursor.close()
            conn.close()

    return False
def get_iblocklist_query(url):
    # "-" işaretini kullanarak sütunu böler ve sadece ikinci kısmı alır
    parts = url.split('-')
    if len(parts) > 1:
        # İkinci kısmı temizle ve başında ve sonundaki boşlukları sil
        return parts[1].strip()
    return url
def is_website_infected(url):
    databases = ['viruswebsites.db', 'viruswebsite.db', 'virusip.db', 'viruswebsitessmall.db', 'abusech.db', 'oldvirusbase.db']
    formatted_url = format_url(url)  # Format the URL
    iblocklist_query = get_iblocklist_query(url)  # Get the iblocklist query
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0 and format_url
    zero_url = "0.0.0.0"  # URL with 0.0.0.0 prefixed
    
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
            "SELECT * FROM virusip WHERE field1 = ?",
            "SELECT * FROM mcafee WHERE field1 = ?",
            "SELECT * FROM full_urls WHERE field3 = ?",
            "SELECT * FROM full_domains WHERE field3 = ?",
            "SELECT * FROM SSBLIP WHERE field2 = ?",
            "SELECT * FROM \"full_ip-port\" WHERE field3 = ?",
            "SELECT * FROM iblocklist WHERE field2 = ?"
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
                    result_iblocklist = cursor.execute(query, (iblocklist_query,)).fetchone()
                    if result_iblocklist:
                        cursor.close()
                        conn.close()
                        return True
                
            except sqlite3.OperationalError:
                pass  # Table is not found, ignore it.

        cursor.close()
        conn.close()

    return False  # Return False if no match is found in any database
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
            elif is_phishing_website(ip):
                print(f"The IP address {ip} is phishing.")
                infected_ips.append(ip)
                disconnect_ip(ip)
                open_phishing_alert_page()
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
def open_phishing_alert_page():
    # Path to current directory
    current_directory = os.getcwd()

    # phishing.html path
    webguard_path = os.path.join(current_directory, 'phishing.html')

    # Open phishing.html with Firefox
    webbrowser.get('firefox').open('file://' + webguard_path)
def open_malicious_tracking_cookie_page():
    # Path to current directory
    current_directory = os.getcwd()

    # trackingcookie.html path
    webguard_path = os.path.join(current_directory, 'trackingcookie.html')

    # Open trackingcookie.html with Firefox
    webbrowser.get('firefox').open('file://' + webguard_path)
def open_phishing_tracking_cookie_page():
    # Path to current directory
    current_directory = os.getcwd()

    # phishingttrackingcookie.html path
    webguard_path = os.path.join(current_directory, 'phishingtrackingcookie.html')

    # Open phishingtrackingcookie.html with Firefox
    webbrowser.get('firefox').open('file://' + webguard_path)
def find_firefox_profile(home_dir=None, default_esr=False):
    try:
        if home_dir is None:
            # Get the user's home directory        
            home_dir = os.path.expanduser("~")

        # Use glob to find Firefox profile folder
        profile_paths = glob.glob(os.path.join(home_dir, ".mozilla/firefox/*default"))

        if default_esr:
            profile_paths.extend(glob.glob(os.path.join(home_dir, ".mozilla/firefox/*default-esr")))

        # Check if .default-release exists and add it to the list if found
        default_release_path = os.path.join(home_dir, ".mozilla/firefox/*default-release")
        if glob.glob(default_release_path):
            profile_paths.extend(glob.glob(default_release_path))

        if profile_paths:
            profile_path = profile_paths[0]
            # Check if places.sqlite exists within the profile directory
            places_db_path = os.path.join(profile_path, "places.sqlite")
            if os.path.exists(places_db_path):
                return profile_path

        # If no profiles found in standard locations or places.sqlite not found, check default-release or default-esr
        fallback_path = os.path.join(home_dir, ".mozilla/firefox/*default-release" if not default_esr else "*default-esr")
        fallback_profiles = glob.glob(fallback_path)
        if fallback_profiles:
            fallback_profile_path = fallback_profiles[0]
            # Check if places.sqlite exists within the fallback profile directory
            fallback_places_db_path = os.path.join(fallback_profile_path, "places.sqlite")
            if os.path.exists(fallback_places_db_path):
                return fallback_profile_path

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
def is_phishing_website0(content):
    # Format the URL
    formatted_url = format_url(content)
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0
    zero_url = "0.0.0.0"  # URL with 0.0.0.0 prefix

    # Database and table information
    db_path = 'viruswebsites.db'
    table_name = 'allphishingdomainsandlinks'
    field_name = 'field1'  # Assuming 'field1' is the field containing the URLs
    # SQL queries to check if the URL is a phishing website
    queries = [
        f"SELECT * FROM {table_name} WHERE {field_name} = ?",
        f"SELECT * FROM {table_name} WHERE {field_name} = ?",
    ]

    for query in queries:
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            result = cursor.execute(query, (formatted_url,)).fetchone()

            if result:
                cursor.close()
                conn.close()
                return True

            # Check ip_prefixed_url and zero_url for phishing
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
        finally:
            cursor.close()
            conn.close()

    return False
def is_website_infected0(content):
    databases = ['viruswebsites.db', 'viruswebsite.db', 'viruswebsitesbig.db', 'virusip.db', 'viruswebsitessmall.db', 'abusech.db', 'oldvirusbase.db']
    formatted_url = format_url(content)  # Format URL
    iblocklist_query = get_iblocklist_query(content)  # Get the iblocklist query
    ip_prefixed_url = "0.0.0.0" + formatted_url  # URL prefixed with 0.0.0.0 and format_url
    zero_url = "0.0.0.0" # URL with 0.0.0.0 prefixed

    # Check if the URL or its variants have already been checked
    if formatted_url in checked_websites:
        display_warning(formatted_url)
        return True  # Website has already been checked

    if ip_prefixed_url in checked_websites:
        display_warning(ip_prefixed_url)
        return True  # Website has already been checked

    if zero_url in checked_websites:
        display_warning(zero_url)
        return True  # Website has already been checked

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
            "SELECT * FROM virusip WHERE field1 = ?",
            "SELECT * FROM mcafee WHERE field1 = ?",
            "SELECT * FROM full_urls WHERE field3 = ?",
            "SELECT * FROM full_domains WHERE field3 = ?",
            "SELECT * FROM paloaltofirewall WHERE field1 = ?",
            "SELECT * FROM SSBLIP WHERE field2 = ?",
            "SELECT * FROM \"full_ip-port\" WHERE field3 = ?",
            "SELECT * FROM iblocklist WHERE field2 = ?"
        ]
        for query in queries:
            try:
                result = cursor.execute(query, (formatted_url,)).fetchone()
                if result:
                    cursor.close()
                    conn.close()
                    checked_websites.add(formatted_url)
                    return True

                # Check ip_prefixed_url and zero_url for phishing
                result_ip = cursor.execute(query, (ip_prefixed_url,)).fetchone()
                if result_ip:
                    cursor.close()
                    conn.close()
                    checked_websites.add(ip_prefixed_url)
                    return True

                result_zero = cursor.execute(query, (zero_url,)).fetchone()
                if result_zero:
                    cursor.close()
                    conn.close()
                    checked_websites.add(zero_url)
                    return True

                # Check with iblocklist query
                result_iblocklist = cursor.execute(query, (iblocklist_query,)).fetchone()  # Assign a value to result_iblocklist
                if result_iblocklist:
                    cursor.close()
                    conn.close()
                    checked_websites.add(formatted_url)
                    return True
            except sqlite3.OperationalError:
                pass  # Table is not found, ignore it.

        cursor.close()
        conn.close()

    return False  # Return False if no match is found in any database  
def check_tracking_cookies(url, cursor):
    try:
        # Remove the preceding dot from the domain if present
        domain = url.lstrip(".")

        # Check for cookies associated with a different domain (potential tracking cookies)
        query = "SELECT name FROM moz_cookies WHERE host != ?;"
        cursor.execute(query, (domain,))
        potential_tracking_cookies = cursor.fetchall()

        return len(potential_tracking_cookies) > 0
    except Exception as e:
        print(f"Error checking potential tracking cookies: {e}")
        return False

def access_firefox_history_continuous():
    try:
        # Find the Firefox profile folder
        profile_path = find_firefox_profile()

        if profile_path is None:
            print("Firefox profile not found.")
            return

        # Create the path to the Firefox history database
        firefox_db_path = os.path.join(profile_path, "places.sqlite")
        cookies_db_path = os.path.join(profile_path, "cookies.sqlite")

        if not os.path.exists(firefox_db_path) or not os.path.exists(cookies_db_path):
            print("Firefox history or cookies database not found.")
            return

        last_visited_websites = []  # To keep track of the last visited websites

        while True:
            # Copy the Firefox history database to a temporary folder
            temp_dir = tempfile.mkdtemp(prefix="firefox_history_")
            copied_places_db_path = os.path.join(temp_dir, "places.sqlite")
            shutil.copy2(firefox_db_path, copied_places_db_path)

            # Connect with the copied places database
            connection_places = sqlite3.connect(copied_places_db_path)
            cursor_places = connection_places.cursor()

            # Copy the Firefox cookies database to a temporary folder
            copied_cookies_db_path = os.path.join(temp_dir, "cookies.sqlite")
            shutil.copy2(cookies_db_path, copied_cookies_db_path)

            # Connect with the copied cookies database
            connection_cookies = sqlite3.connect(copied_cookies_db_path)
            cursor_cookies = connection_cookies.cursor()

            # Get visited sites with a query
            query = "SELECT title, url FROM moz_places ORDER BY id DESC LIMIT 5;"
            cursor_places.execute(query)
            results = cursor_places.fetchall()

            # Scan visited websites and show results
            for row in results:
                title, url = row
                print(f"Scanning URL: {url}")

                # Check if the URL is infected
                is_infected = is_website_infected(url)

                # Check if the URL is a phishing website
                is_phishing = is_phishing_website(url)

                # Check if tracking cookies are found
                tracking_cookies_found = check_tracking_cookies(url, cursor_cookies)

                # Extract IP address from the URL
                ip_address = extract_ip_from_url(url)

                if tracking_cookies_found:
                    if is_infected:
                        print("Malicious tracking cookie found on an infected website. URL:", url)
                        print(f"Malicious tracking cookie IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the IP address
                        open_malicious_tracking_cookie_page()
                    elif is_phishing:
                        print("Phishing tracking cookie found on an infected website. URL:", url)
                        print(f"Phishing tracking cookie IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the IP address
                        open_phishing_tracking_cookie_page()
                    else:
                        print("Tracking cookie not found on the website. URL:", url)

                    if ip_address:
                        print(f"Cookie IP address: {ip_address}")
                    else:
                        print("No IP address found for the given URL:", url)
                elif is_infected:
                    print("The website is infected.")
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"Infected IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the infected IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_webguard_page()  # Open the webguard.html file
                elif is_phishing:
                    print("The website is phishing.")
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"Phishing IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the phishing IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_phishing_alert_page()  # Open the phishing.html file
                else:
                    print("The website is clean.")

                if len(last_visited_websites) >= 5:
                    last_visited_websites.pop(0)  # Remove the oldest visited website
                last_visited_websites.append(url)

            # Close the connections and clean the temporary folder
            connection_places.close()
            connection_cookies.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
            connection_cookies.close()

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
        cookies_db_path = os.path.join(profile_path, "cookies.sqlite")

        if not os.path.exists(firefox_db_path) or not os.path.exists(cookies_db_path):
            print("Firefox history or cookies database not found.")
            return

        last_visited_websites = []  # To keep track of the last visited websites

        while True:
            # Copy the Firefox history database to a temporary folder
            temp_dir = tempfile.mkdtemp(prefix="firefox_history_")
            copied_places_db_path = os.path.join(temp_dir, "places.sqlite")
            shutil.copy2(firefox_db_path, copied_places_db_path)

            # Connect with the copied places database
            connection_places = sqlite3.connect(copied_places_db_path)
            cursor_places = connection_places.cursor()

            # Copy the Firefox cookies database to a temporary folder
            copied_cookies_db_path = os.path.join(temp_dir, "cookies.sqlite")
            shutil.copy2(cookies_db_path, copied_cookies_db_path)

            # Connect with the copied cookies database
            connection_cookies = sqlite3.connect(copied_cookies_db_path)
            cursor_cookies = connection_cookies.cursor()

            # Get visited sites with a query
            query = "SELECT title, url FROM moz_places ORDER BY id DESC LIMIT 5;"
            cursor_places.execute(query)
            results = cursor_places.fetchall()

            # Scan visited websites and show results
            for row in results:
                title, url = row
                print(f"Scanning URL: {url}")

                # Check if the URL is infected
                is_infected = is_website_infected(url)

                # Check if the URL is a phishing website
                is_phishing = is_phishing_website(url)

                # Check if tracking cookies are found
                tracking_cookies_found = check_tracking_cookies(url, cursor_cookies)

                # Extract IP address from the URL
                ip_address = extract_ip_from_url(url)

                if tracking_cookies_found:
                    if is_infected:
                        print("Malicious tracking cookie found on an infected website. URL:", url)
                        print(f"Malicious tracking cookie IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the IP address
                        open_malicious_tracking_cookie_page()
                        delete_file(file_path)
                    elif is_phishing:
                        print("Phishing tracking cookie found on an infected website. URL:", url)
                        print(f"Phishing tracking cookie IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the IP address
                        open_phishing_tracking_cookie_page()
                        delete_file(file_path)
                    else:
                        print("Tracking cookie not found on the website. URL:", url)

                    if ip_address:
                        print(f"Cookie IP address: {ip_address}")
                    else:
                        print("No IP address found for the given URL:", url)
                elif is_infected:
                    print("The website is infected.")
                    delete_file(file_path)
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"Infected IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the infected IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_webguard_page()  # Open the webguard.html file
                elif is_phishing:
                    print("The website is phishing.")
                    delete_file(file_path)
                    ip_address = extract_ip_from_url(url)
                    if ip_address:
                        print(f"Phishing IP address: {ip_address}")
                        disconnect_ip(ip_address)  # Disconnect the phishing IP address
                        if last_visited_websites:
                            last_visited_websites.pop()  # Remove the last visited website
                            open_phishing_alert_page()  # Open the phishing.html file
                else:
                    print("The website is clean.")

                if len(last_visited_websites) >= 5:
                    last_visited_websites.pop(0)  # Remove the oldest visited website
                last_visited_websites.append(url)

            # Close the connections and clean the temporary folder
            connection_places.close()
            connection_cookies.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
            connection_cookies.close()

    except Exception as e:
        print(f"Error accessing Firefox history: {e}")
def scan_file_for_malicious_content(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except Exception as e:
        return "Error reading file " + file_path + ": " + str(e)
    if re.search(r'rm\s+-rf /', content):
        print ("Infected file (Malicious Content rm -rf /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chmod -R ugo-rwx /', content):
        print ("Infected file (Malicious Content chmod -R ugo-rwx /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chattr\s+-R\s+\+i\s+/', content):
        print ("Infected file (Malicious Content chattr -R +i /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chown /', content):
        print ("Infected file (Malicious Content chown /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mkfs\.ext4', content):
        print("Infected file (Malicious Content - mkfs.ext4): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chmod 777 /', content):
        print("Infected file (Malicious Content - chmod 777 /): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'fdisk /dev/sd[a-z]', content):
        print("Infected file (Malicious Content Disk Overwriter): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'dd if=/dev/zero of=/dev/sd[a-z]', content):                            
         print("Infected file (Malicious Content dd Disk Overwriter): " + file_path)
         delete_file(file_path)  # Remove the infected file
         return "Infected file according to malware content check: " + file_path
    if re.search(r'ufw\s+disable', content):
        print("Infected file (Malicious Content ufw disable): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'shutdown', content):
        print("Infected file (Malicious Content - shutdown): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'nc -l -p 4444 -e /bin/bash', content) or re.search(r'ncat -l -p 4444 -e /bin/bash', content):
        print("Infected file (Malicious Content - Reverse Shell): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'init 0', content):
        print("Infected file (Malicious Content - init 0): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'init 6', content):
        print("Infected file (Malicious Content - init 6): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};', content):
        print("Infected file (Malicious Content - Fork Bomb): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'wget\s+https://', content) and re.search(r'\s+-O\s+\w+\.\w+', content):
        print("Infected file (Malicious Content - wget with -O): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mkfifo\s+/tmp/backpipe;\s+/bin/sh\s+0</tmp/backpipe\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+1>/tmp/backpipe', content):
        print("Infected file (Malicious Content - FIFO Pipe and Netcat): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path    
    if re.search(r'mkfifo\s+/tmp/fifo;\s+cat\s+/tmp/fifo\s+\|\s+/bin/sh\s+-i\s+2>&1\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+>\s+/tmp/fifo', content):
        print("Infected file (Malicious Content - FIFO Pipe, Shell, and Netcat): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'openssl\s+enc\s+-aes-256-cbc', content):
        print("Infected file (Malicious (Ransomware) Content - openssl enc): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'cat\s+>\s+/dev/sda', content):
        print("Infected file (Malicious Content - cat > /dev/sda): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mv\s+/bin/bash\s+/bin/bash\.bak', content):
        print("Infected file (Malicious Content - Disable Bash): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'find\s+/\s+-name\s+"*.log"', content):
        print("Infected file (Malicious Content - Find log files): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'-exec\s+rm\s+-f\s+{}\s+;', content):
        print("Infected file (Malicious Content - Remove log files): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'rm\s+-f\s+/lib/libc\.so\.6', content):
        print("Infected file (Malicious Content - Remove libc.so.6): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mkfifo\s+/\w+/\w+;\s+\S+\s+/\w+/\w+\s+\|\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+', content):
        print("Infected file (Malicious Content - FIFO): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\S+\s+\|\s+\S+', content):
        print("Infected file (Malicious Content - Pipe): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\S+\s+/bin/sh\s+-i', content):
        print("Infected file (Malicious Content - Shell): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
        print( "Excluded IP/Host: " + file_path)
    if is_website_infected0(content) or is_website_infected0("www."+format_url(content) or (format_url(content))):
        print("Infected file (Malicious Website Or IP Content): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if is_phishing_website0(content) or is_phishing_website0("www." + format_url(content)) or is_phishing_website0(format_url(content)):
        print("Phishing file (Phishing Website Or IP Content): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Phishing file according to malware content check: " + file_path
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
            elif is_phishing_website(response.content):
                print("Phishing website found in sandbox output")
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
    if re.search(r'rm\s+-rf /', content):
        print("Infected file (Malicious Content rm -rf /): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chmod -R ugo-rwx /', content):
        print ("Infected file (Malicious Content chmod -R ugo-rwx /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chattr\s+-R\s+\+i\s+/', content):
        print ("Infected file (Malicious Content chattr -R +i /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chown /', content):
        print ("Infected file (Malicious Content chown /): " + file_path)
        delete_file(file_path) # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b', content, re.IGNORECASE):
        print("Excluded IP/Host: " + file_path)
    if is_website_infected0(content) or is_website_infected("www." + format_url(content)) or is_website_infected(format_url(content)):
        print("Infected file (Malicious Website Content): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return"Infected file according to malware content check: " + file_path
    if is_phishing_website0(content) or is_phishing_website("www." + format_url(content)) or is_phishing_website(format_url(content)):
        print("Phishing file (Phishing Website Content): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return"Infected file according to malware content check: " + file_path
    if re.search(r'mkfs\.ext4', content):
        print("Infected file (Malicious Content - mkfs.ext4): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'fdisk /dev/sd[a-z]', content):
        print("Infected file (Malicious Content Disk Overwriter): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'dd if=/dev/zero of=/dev/sd[a-z]', content):                            
         print("Infected file (Malicious Content dd Disk Overwriter): " + file_path)
         delete_file(file_path)  # Remove the infected file
    if re.search(r'ufw\s+disable', content):
        print("Infected file (Malicious Content ufw disable): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'shutdown', content):
        print("Infected file (Malicious Content - shutdown): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'nc -l -p 4444 -e /bin/bash', content) or re.search(r'ncat -l -p 4444 -e /bin/bash', content):
        print("Infected file (Malicious Content - Reverse Shell): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'chmod 777 /', content):
        print("Infected file (Malicious Content - chmod 777 /): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'init 0', content):
        print("Infected file (Malicious Content - init 0): " + file_path)
        delete_file(file_path)  # Remove the infected file
    if re.search(r'init 6', content):
        print("Infected file (Malicious Content - init 6): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};', content):
        print("Infected file (Malicious Content - Fork Bomb): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'wget\s+https://', content) and re.search(r'\s+-O\s+\w+\.\w+', content):
        print("Infected file (Malicious Content - wget with -O): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mkfifo\s+/tmp/backpipe;\s+/bin/sh\s+0</tmp/backpipe\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+1>/tmp/backpipe', content):
        print("Infected file (Malicious Content - FIFO Pipe and Netcat): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path    
    if re.search(r'mkfifo\s+/tmp/fifo;\s+cat\s+/tmp/fifo\s+\|\s+/bin/sh\s+-i\s+2>&1\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+>\s+/tmp/fifo', content):
        print("Infected file (Malicious Content - FIFO Pipe, Shell, and Netcat): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'openssl\s+enc\s+-aes-256-cbc', content):
        print("Infected file (Malicious (Ransomware) Content - openssl enc): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'cat\s+>\s+/dev/sda', content):
        print("Infected file (Malicious Content - cat > /dev/sda): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mv\s+/bin/bash\s+/bin/bash\.bak', content):
        print("Infected file (Malicious Content - Disable Bash): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'find\s+/\s+-name\s+"*.log"', content):
        print("Infected file (Malicious Content - Find log files): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'-exec\s+rm\s+-f\s+{}\s+;', content):
        print("Infected file (Malicious Content - Remove log files): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'rm\s+-f\s+/lib/libc\.so\.6', content):
        print("Infected file (Malicious Content - Remove libc.so.6): " + file_path)
        delete_file(file_path)  # Remove the infected file
        return "Infected file according to malware content check: " + file_path
    if re.search(r'mkfifo\s+/\w+/\w+;\s+\S+\s+/\w+/\w+\s+\|\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+', content):
        print("Infected file (Malicious Content - FIFO): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\S+\s+\|\s+\S+', content):
        print("Infected file (Malicious Content - Pipe): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    if re.search(r'\S+\s+/bin/sh\s+-i', content):
        print("Infected file (Malicious Content - Shell): " + file_path)
        delete_file(file_path)
        return "Infected file according to malware content check: " + file_path
    else:
        return "Clean file according to malware content check: " + file_path
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
                 if re.search(r'mkfs\.ext4', content):
                     print("Infected file (Malicious Content - mkfs.ext4): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'rm\s+-rf /', content):
                     print("Infected file (Malicious Content - rm -rf /): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'chmod -R ugo-rwx /', content):
                     print ("Infected file (Malicious Content chmod -R ugo-rwx /): " + file_path)
                     delete_file(file_path) # Remove the infected file
                     continue
                 if re.search(r'chattr\s+-R\s+\+i\s+/', content):
                     print ("Infected file (Malicious Content chattr -R +i /): " + file_path)
                     delete_file(file_path) # Remove the infected file
                     continue
                 if re.search(r'chown /', content):
                     print ("Infected file (Malicious Content chown /): " + file_path)
                     delete_file(file_path) # Remove the infected file
                     continue
                 if re.search(r'shutdown', content):
                    print("Infected file (Malicious Content - shutdown): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'ufw\s+disable', content):
                    print("Infected file (Malicious Content ufw disable): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'fdisk /dev/sd[a-z]', content):
                    print("Infected file (Malicious Content Disk Overwriter): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'dd if=/dev/zero of=/dev/sd[a-z ]', content):                            
                    print("Infected file (Malicious Content dd Disk Overwriter): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'chmod 777 /', content):
                    print("Infected file (Malicious Content - chmod 777 /): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'init 0', content):
                    print("Infected file (Malicious Content - init 0): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'nc -l -p 4444 -e /bin/bash', content) or re.search(r'ncat -l -p 4444 -e /bin/bash', content):
                     print("Infected file (Malicious Content - Reverse Shell): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'init 6', content):
                    print("Infected file (Malicious Content - init 6): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};', content):
                    print("Infected file (Malicious Content - Fork Bomb): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'wget\s+https://', content) and re.search(r'\s+-O\s+\w+\.\w+', content):
                     print("Infected file (Malicious Content - wget with -O): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'mkfifo\s+/tmp/backpipe;\s+/bin/sh\s+0</tmp/backpipe\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+1>/tmp/backpipe', content):
                     print("Infected file (Malicious Content - FIFO Pipe and Netcat): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'\S+\s+/bin/sh\s+-i', content):
                     print("Infected file (Malicious Content - Shell): " + file_path)
                     delete_file(file_path)
                     continue
                 if re.search(r'mkfifo\s+/tmp/fifo;\s+cat\s+/tmp/fifo\s+\|\s+/bin/sh\s+-i\s+2>&1\s+\|\s+nc\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+>\s+/tmp/fifo', content):
                     print("Infected file (Malicious Content - FIFO Pipe, Shell, and Netcat): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'openssl\s+enc\s+-aes-256-cbc', content):
                     print("Infected file (Malicious (Ransomware) Content - openssl enc): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'cat\s+>\s+/dev/sda', content):
                     print("Infected file (Malicious Content - cat > /dev/sda): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'mv\s+/bin/bash\s+/bin/bash\.bak', content):
                     print("Infected file (Malicious Content - Disable Bash): " + file_path)
                     delete_file(file_path)  # Remove the infected file
                     continue
                 if re.search(r'find\s+/\s+-name\s+"*.log"', content):
                     print("Infected file (Malicious Content - Find log files): " + file_path)
                     delete_file(file_path)
                     continue
                 if re.search(r'-exec\s+rm\s+-f\s+{}\s+;', content):
                    print("Infected file (Malicious Content - Remove log files): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'rm\s+-f\s+/lib/libc\.so\.6', content):
                    print("Infected file (Malicious Content - Remove libc.so.6): " + file_path)
                    delete_file(file_path)  # Remove the infected file
                    continue
                 if re.search(r'mkfifo\s+/\w+/\w+;\s+\S+\s+/\w+/\w+\s+\|\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+', content):
                    print("Infected file (Malicious Content - FIFO): " + file_path)
                    delete_file(file_path)
                    continue
                 if re.search(r'\S+\s+\|\s+\S+', content):
                   print("Infected file (Malicious Content - Pipe): " + file_path)
                   delete_file(file_path)
                   continue
                 if is_phishing_website0(content) or is_phishing_website0("www." + format_url(content)) or is_phishing_website0(format_url(content)):
                   print("Phishing file (Phishing Website Content): " + file_path)
                   delete_file(file_path)  # Remove the infected file
                   continue
                 if is_website_infected0(content) or is_website_infected0("www."+format_url(content) or (format_url(content))):
                   print("Infected file (Malicious Website Content):", file_path)
                   delete_file(file_path)
                   continue
                 print("Clean file according to malware content check:", file_path)
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
            elif is_phishing_website(ip):
                print(f"The IP address {ip} is phishing.")
                infected_ips.append(ip)
                disconnect_ip(ip)
                open_phishing_alert_page()
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
                ssdeep_hash = calculate_ssdeep(file_path)
                tlsh_hash = calculate_tlsh(file_path)
                print(f"File: {file_path}")
                print(f"MD5 Hash: {md5_hash}")
                print(f"SHA-1 Hash: {sha1_hash}")
                print(f"SHA-256 Hash: {sha256_hash}")
                print(f"SSDEEP Hash: {ssdeep_hash}")
                print(f"TLSH Hash: {tlsh_hash}")
                print("-" * 40)
    else:
        print("Invalid folder path.")
# Get the current username
current_username = getpass.getuser()

# Function to filter out hidden directories
def is_hidden(directory):
    return not directory.startswith('.')

# Get the user's home directory
home_directory = os.path.expanduser(f"~{current_username}")

# Get directories in the user's home directory, excluding hidden directories
directories_to_monitor = [
    os.path.join(home_directory, d)
    for d in os.listdir(home_directory)
    if os.path.isdir(os.path.join(home_directory, d)) and is_hidden(d)
]
class FileChangeHandler(pyinotify.ProcessEvent):
    def __init__(self, suspicious_file_path):
        self.suspicious_file_path = suspicious_file_path
        self.suspicious_file_hash = self.calculate_file_hash(suspicious_file_path)
        super().__init__()

    def process_IN_CLOSE_WRITE(self, event):
        if not event.dir:
            file_path0 = event.pathname
            original_extension = os.path.splitext(self.suspicious_file_path)[1]
            new_extension = os.path.splitext(file_path0)[1]

            # Ignore changes to files with a .db extension
            if new_extension == '.db':
                pass
            elif original_extension != new_extension:
                print(f"File extension has changed: {self.suspicious_file_path} -> {file_path0}")
                new_file_hash = self.calculate_file_hash(file_path0)

                if new_file_hash != self.suspicious_file_hash:
                    print(f"File content has changed: {self.suspicious_file_path} -> {file_path0}")
                    delete_file(self.suspicious_file_path)  # Delete suspicious file
            else:
                self.handle_file_change(file_path0)
    def calculate_file_hash(self, file_path0):
        hasher = hashlib.sha256()
        with open(file_path0, 'rb') as file:
            while True:
                data = file.read(65536)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    def handle_file_change(self, file_path0):
        try:
            # Attempt to read the file as UTF-8
            with open(file_path0, 'r', encoding='utf-8') as file:
                file.read()
        except UnicodeDecodeError:
            # File is not readable as UTF-8 (potentially encrypted)
            print(f"File is not readable as UTF-8: {file_path0}")
            delete_file(self.suspicious_file_path)  # Delete suspicious file

def start_monitoring(suspicious_file_path, file_path0):
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_CLOSE_WRITE

    event_handler = FileChangeHandler(suspicious_file_path)
    event_handler.file_path0 = file_path0  # Store the current file path
    notifier = pyinotify.Notifier(wm, event_handler)

    for directory in directories_to_monitor:
        wm.add_watch(directory, mask, rec=True)

    print("File change monitor started.")

    try:
        notifier.loop()
    except KeyboardInterrupt:
        notifier.stop()
# Constants for tuning the detection sensitivity
THRESHOLD_KEYPRESS_COUNT = 15  # Adjust this threshold as needed

# Global variables to keep track of keyboard events
key_events = []
rat_detected = False

# Function to handle key presses
def on_key_press(stdscr):
    while True:
        char = stdscr.getch()
        key = chr(char) if char >= 32 and char <= 126 else f"Keycode {char}"
        key_events.append(key)
        
        if len(key_events) >= THRESHOLD_KEYPRESS_COUNT:
            detect_rat()

# Function for RAT detection
def detect_rat():
    global rat_detected
    rat_detected = True
    print("Possible Remote Access Trojan (RAT) activity detected!")
def check_website_in_blist():
    # Get the website URL from the user
    website_url = input("Please enter the website URL to check: ")
    try:
        # Connect to or create the database (if it doesn't exist)
        conn = sqlite3.connect("urlbl2.db")
        cursor = conn.cursor()

        # Search for the URL in the blist table in the database
        cursor.execute("SELECT * FROM blist WHERE url=?", (website_url,))
        result = cursor.fetchone()

        if result:
            print(f"{website_url} found in the blist table. This website is known.")
        else:
            print(f"{website_url} not found in the blist table. This site is not known. Maybe it's a clean website. Check with other databases.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

    finally:
        # Close the database connection
        conn.close()
def find_connected_ips(file_path,exe_path):
    connected_ips = set()

    try:
        # Open the file and read its content
        with open(file_path, 'rb') as file:
            content = file.read()

        # Use a regex pattern to find IP addresses
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, content.decode('utf-8'))

        # Check each IP address and detect connections
        for ip in ips:
            try:
                socket.inet_aton(ip)  # Check for a valid IP address
                connected_ips.add(ip)
            except socket.error:
                pass

    except Exception as e:
        print(f'Error: {str(e)}')

    return connected_ips
def backup_mbr(backup_dir):
    # Get MBR
    backup_path = os.path.join(backup_dir, "mbr_backup")
    os.system("sudo dd if=/dev/sda of=" + backup_path + " bs=512 count=1")
def restore_mbr(backup_path):
    # Upload old MBR
    os.system("sudo dd if=" + backup_path + " of=/dev/sda bs=512 count=1")
def check_mbr_overwrite(file_path, backup_dir):
    # Check MBR
    backup_path = os.path.join(backup_dir, "mbr_backup")

    if not os.path.exists(backup_path):
        print("MBR backup not found.")
        return

    with open(file_path, 'rb') as current_file:
        current_mbr = current_file.read(512)

    with open(backup_path, 'rb') as backup_file:
        backup_mbr = backup_file.read(512)
    # Compare MBR hashes
    current_hash = hashlib.sha256(current_mbr).hexdigest()
    backup_hash = hashlib.sha256(backup_mbr).hexdigest()

    if current_hash != backup_hash:
        print("MBR has changed. Restoring the backup MBR...")
        restore_mbr(backup_path)
        print("MBR has been restored.")     
        # Delete the file
        delete_file(file_path)
def delete_selected_files(files, selected_file):
    try:
        os.remove(selected_file)
        print(f"{selected_file} has been deleted.")
        files.remove(selected_file)
    except Exception as e:
        print(f"Error deleting {selected_file}: {e}")

def extract_ips_from_strace(file_path, exe_path):
    try:
        # Check if the executable file exists
        if not os.path.exists(exe_path) or not os.path.isfile(exe_path):
            print(f"Executable file not found: {exe_path}")
            return []

        # Get the absolute executable path
        abs_exe_path = os.path.abspath(exe_path)

        # Run strace and monitor connect calls
        strace_command = ["strace", "-e", "connect", "-f", "-o", file_path, abs_exe_path]
        subprocess.check_output(strace_command)

        # Read the strace output and extract IP addresses
        ips = set()
        with open(file_path, "r") as strace_file:
            for line in strace_file:
                if "connect(" in line:
                    parts = line.split()
                    ip = parts[parts.index("->") + 1].split(":")[0]
                    ips.add(ip)
                    print(f"Detected IP Address: {ip}")

                    # Check if the IP is malicious
                    if is_website_infected(ip):
                        print(f"Malicious IP Detected: {ip}")
                        # Perform action: Delete the file
                        delete_file(abs_exe_path)
                    # Check if the IP is phishing
                    elif is_phshing_website(ip):
                        print(f"Phishing IP Detected: {ip}")
                        # Perform action: Delete the file
                        delete_file(abs_exe_path)  
        return list(ips)  # Return the list of IP addresses
    except subprocess.CalledProcessError as e:
        print("Error: subprocess call returned a non-zero exit status")
        print(f"Command: {e.cmd}")
        print(f"Output: {e.output}")
        return []

def monitoring_running_processes():
    try:
        temp_dir = tempfile.mkdtemp(prefix="running_file_scan_")
        running_files = []

        for root, dirs, files in os.walk("/proc"):
            for filename in files:
                if filename == "exe":
                    exe_link = os.path.join(root, filename)
                    try:
                        exe_path = os.readlink(exe_link)
                        running_files.append(exe_path)
                    except OSError:
                        pass

        # Print the list of running files
        print("Running Files:")
        for i, file in enumerate(running_files):
            print(f"{i + 1}. {file}")

        # Implement further actions as needed

    except Exception as e:
        print(f"Error in monitoring_running_processes: {e}")
def continuously_monitor_file(file_path):
    while True:
        # Scan the file for IP addresses
        ips_detected = scan_single_file(file_path)
        if ips_detected:
            print("Detected IP Addresses:")
            for ip_detected in ips_detected:
                print(ip_detected)

        # Check the content
        content = open(file_path).read()
        if is_website_infected0(content):
            # If infected, take actions for malicious content
            delete_file(file_path)
            for ip_detected in ips_detected:
                disconnect_ip(ip_detected)
                open_webguard_page() # Open the WebGuard.html file
        elif is_phishing_website0(content):
            # If phishing, take actions for phishing content
            delete_file(file_path)
            for ip_detected in ips_detected:
                disconnect_ip(ip_detected)
                open_phishing_alert_page()  # Open the phishing.html file
        else:
            print("The file is clean.")
def scan_single_file(file_path, exe_path):
    try:
        # Get the absolute file path
        abs_file_path = os.path.abspath(file_path)

        # Check if the file exists
        if not os.path.exists(abs_file_path) or not os.path.isfile(abs_file_path):
            print(f"File not found: {abs_file_path}")
            return []

        # Scan the file using strace and monitor connect calls
        strace_command = ["strace", "-e", "connect", "-f", "-o", "strace_output.log", exe_path, abs_file_path]
        subprocess.check_call(strace_command)

        # Read the strace output and extract IP addresses
        ips = set()
        with open("strace_output.log", "r") as strace_file:
            for line in strace_file:
                if "connect(" in line:
                    parts = line.split()
                    ip = parts[parts.index("->") + 1].split(":")[0]
                    ips.add(ip)
                    print(f"Detected IP Address: {ip}")

        return list(ips)  # Return the list of IP addresses
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        return []
def perform_folder_scan():
    folder_path = filedialog.askdirectory()
    if folder_path:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            executor.submit(scan_folder_with_clamscan, folder_path)
            executor.submit(scan_folder_parallel, folder_path)
            executor.submit(scan_folder_with_malware_content_check, folder_path)

def check_website_infection():
    website_url = simpledialog.askstring("Website URL", "Enter the website URL to check:")
    if website_url:
        if is_website_infected(website_url):
            messagebox.showinfo("Website Status", "The website is infected.")
        elif is_phishing_website(website_url):
            messagebox.showinfo("Website Status", "The website is phishing.")
        else:
            messagebox.showinfo("Website Status", "The website is clean.")
    return False
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Program")

        # Create the menu
        self.create_menu()

        # Create a Text widget to simulate console
        self.console_text = tk.Text(self.root, wrap="word", height=20, width=80)
        self.console_text.pack(expand=True, fill=tk.BOTH)
        # Add a button to press Enter
        self.enter_button = tk.Button(self.root, text="Press Enter", command=self.press_enter)
        self.enter_button.pack()
        # Initialize rkhunter_process
        self.rkhunter_process = None
    def create_menu(self):
        menu = tk.Menu(self.root)
        self.root.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Perform a folder scan", command=self.perform_folder_scan0)

        rootkit_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Rootkit", menu=rootkit_menu)
        rootkit_menu.add_command(label="Run chkrootkit", command=self.run_chkrootkit)
        rootkit_menu.add_command(label="Run rkhunter", command=self.run_rkhunter)

        website_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Website", menu=website_menu)
        website_menu.add_command(label="Check Website in Blist", command=self.check_website_in_blist0)

        firefox_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Firefox", menu=firefox_menu)
        firefox_menu.add_command(label="Check Firefox Profile", command=self.check_firefox_profile)
    def perform_folder_scan0(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_clamscan = executor.submit(scan_folder_with_clamscan, folder_path)
                future_parallel = executor.submit(scan_folder_parallel, folder_path)
                future_malware_content = executor.submit(scan_folder_with_malware_content_check, folder_path)

                # Wait for all threads to complete
                concurrent.futures.wait([future_clamscan, future_parallel, future_malware_content])

                # Get the results from the futures
                result_clamscan = future_clamscan.result()
                result_parallel = future_parallel.result()
                result_malware_content = future_malware_content.result()

                # Update labels to show results
                self.update_results_label(f"Clamscan Result: {result_clamscan}\n"
                                          f"Parallel Scan Result: {result_parallel}\n"
                                          f"Malware Content Check Result: {result_malware_content}")
    def check_website_in_blist0(self):
        website_url = simpledialog.askstring("Check Website in Blist", "Enter the website URL to check:")
        if not website_url:
            return  # User cancelled or entered an empty URL

        try:
            conn = sqlite3.connect("urlbl2.db")
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM blist WHERE url=?", (website_url,))
            result = cursor.fetchone()

            if result:
                result_text = f"{website_url} found in the blist table. This website is known."
            else:
                result_text = f"{website_url} not found in the blist table. This site is not known. Maybe it's a clean website. Check with other databases."

            self.update_console(result_text)

        except sqlite3.Error as e:
            self.update_console(f"Database error: {e}")

        finally:
            conn.close()

    def update_console(self, text):
        # Append the text to the console
        self.console_text.insert(tk.END, text + '\n')
        # Scroll to the end
        self.console_text.see(tk.END)
    def press_enter(self):
        # Simulate pressing Enter by writing a newline character to the process
        if self.rkhunter_process:
            self.rkhunter_process.stdin.write('\n')
            self.rkhunter_process.stdin.flush()
    def press_enter(self):
        # Simulate pressing Enter by writing a newline character to the process
        if self.rkhunter_process:
            self.rkhunter_process.stdin.write('\n')
            self.rkhunter_process.stdin.flush()
    def run_rkhunter(self):
        try:
            # Run rkhunter with sudo
            command = ['sudo', 'rkhunter', '--check']

            # Create a new window for the console
            console_window = tk.Toplevel(self.root)
            console_window.title("rkhunter Console")

            # Create a text widget to display the output
            console_text = tk.Text(console_window, wrap=tk.WORD)
            console_text.pack(expand=True, fill=tk.BOTH)

            # Function to read and display stdout and stderr
            def read_output():
                while True:
                    line = self.rkhunter_process.stdout.readline()
                    if not line and self.rkhunter_process.poll() is not None:
                        break

                    console_text.insert(tk.END, line)
                    console_text.see(tk.END)
                    console_window.update()

            # Start the process and display the output in the console
            self.rkhunter_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)

            # Start a thread to read and display stdout and stderr
            output_thread = threading.Thread(target=read_output)
            output_thread.start()

        except Exception as e:
            self.update_results_label(f"Error running rkhunter: {e}")
    def update_console(self, text):
        # Append the text to the console
        self.console_text.insert(tk.END, text + '\n')
        # Scroll to the end
        self.console_text.see(tk.END)
    def run_chkrootkit(self):
        try:
            result = subprocess.run(['sudo', 'chkrootkit'], capture_output=True, text=True)
            self.update_console("=== chkrootkit Scan Results ===")
            for line in result.stdout.split('\n'):
                self.update_console(line)
        except Exception as e:
            self.update_console(f"Error running chkrootkit: {e}")
    def update_console(self, text):
        # Append the text to the console
        self.console_text.insert(tk.END, text + '\n')
        # Scroll to the end
        self.console_text.see(tk.END)
    def update_results(self):
        while True:
            # Get the result from the queue and insert it into the Listbox
            result = self.result_queue.get()
            self.result_listbox.insert(tk.END, result)
    def check_firefox_profile(self):
        home_dir = filedialog.askdirectory(title="Select Firefox Profile Directory", initialdir=os.path.expanduser("~"))
        if home_dir:
            profile_path = find_firefox_profile(home_dir)
            if profile_path:
                self.update_results_label(f"Found Firefox profile at: {profile_path}")
            else:
                self.update_results_label("No Firefox profile found.")

    # Add a method to update the results label
    def update_results_label(self, text):
        # Destroy previous label
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create and display the new label
        result_label = tk.Label(self.root, text=text)
        result_label.pack()
def main():
    while True:
        print("You need to install firejail, strace, chkrootkit, clamav and rkhunter.")
        print("You need to give root access to the program.")
        print("Select an option:")
        print("1. Perform a folder scan")
        print("2. Check if a website is infected by typing the URL")
        print("3. Real-time web and file protection")
        print("4. Perform an intuitive sandbox file scan (Run on a VM and perform a file scan first)")
        print("5. Calculate hashes of files in a folder")
        print("6. Are someone clicking on your keyboard? Test it!")
        print("7. Check urlbl2.db for known websites. Don't add www. or http etc")
        print("8. Rootkit scan with chkrootkit")
        print("9. Rootkit scan with rkhunter")
        print("10.Check Firefox profile")
        print("11.User Interface Mode")
        print("12. Exit")
        
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
            website_url = input("Enter the website URL to check: ")
            if is_website_infected(website_url):
                print("The website is infected.")
            elif is_phishing_website(website_url):
                print("The website is phishing.")
            else:
                print("The website is clean.")   
        elif choice == "3":
            # Prompt the user to enter the home directory
            home_dir = input("Enter the home directory and username for Firefox history scan (e.g., /home/yourusername If you haven't started it as sudo, leave it blank): ")
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                executor.submit(real_time_web_protection)
                executor.submit(access_firefox_history_continuous)
                executor.submit(scan_running_files_with_custom_and_clamav_continuous)
                executor.submit(monitoring_running_processes)        
        elif choice == "4":
            file_path = input("Enter the path of the file to intuitively scan: ").strip("'")
                 # Check if the file exists before proceeding
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
                continue
            # Check if the file is empty (0-byte size)
            if os.path.getsize(file_path) == 0:
               print("File is empty (0-byte size), rejecting.")
               return
            # Prompt the user to enter the home directory
            home_dir = input("Enter the home directory and username for Firefox history scan (e.g., /home/yourusername If you haven't started it as sudo, leave it blank): ")

            suspicious_file_path = file_path
            exe_path = file_path

            # Start functions in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                future4 = executor.submit(start_monitoring, suspicious_file_path, file_path)
                future1 = executor.submit(access_firefox_history_continuous0, file_path)
                future2 = executor.submit(scan_file_for_malicious_content, file_path)
                future3 = executor.submit(real_time_web_protection0, file_path)
                future5 = executor.submit(check_mbr_overwrite, file_path)
                future6 = executor.submit(find_connected_ips, file_path)
                future7 = executor.submit(continuously_monitor_file, file_path)
                future8 = executor.submit(extract_ips_from_strace, exe_path)

                # Wait for all functions to complete
                concurrent.futures.wait([future1, future2, future3, future4, future5, future6, future7, future8])

                # Get the results from the futures
                result1 = future1.result()
                result2 = future2.result()
                result3 = future3.result()
                result4 = future4.result()
                result5 = future5.result()
                result6 = future6.result()
                result7 = future7.result()
                result8 = future8.result()

                # Print or handle results as needed
                print("access_firefox_history_continuous0 result:", result1)
                print("start_monitoring result:", result4)
                print("check_mbr_ovfile_for_malicious_content result:", result2)
                print("real_time_web_protection0 result:", result3)
                print("check_mbr_overwrite result:", result5)
                print("find_connected_ips result:", result6)
                print("continuously_monitor_file result:", result7)
                print("extract_ips_from_strace result:", result8)     
        elif choice == "5":
            folder_path = input("Enter the path of the folder to calculate hashes for: ")
            calculate_hashes_in_folder(folder_path)      
        elif choice == "6":
            curses.wrapper(on_key_press)     
        elif choice == "7":
            check_website_in_blist()
        elif choice == "8":
            subprocess.run(['sudo', 'chkrootkit'])
        elif choice == "9":
            subprocess.run(['sudo', 'rkhunter', '--check'])
        elif choice == "10":
            home_dir = input("Enter the home directory and username (e.g., /home/yourusername If you haven't started it as sudo, leave it blank):  ").strip()
            profile_path = find_firefox_profile(home_dir)
            if profile_path:
                print(f"Found Firefox profile at: {profile_path}")
            else:
                print("No Firefox profile found.")
        elif choice == "11":
            print("UI Mode Enabled")
            root = tk.Tk()
            gui = AntivirusGUI(root)
            root.mainloop()
        elif choice == "12":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")
if __name__ == "__main__":
    main()