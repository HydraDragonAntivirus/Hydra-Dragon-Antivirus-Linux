import "pe"
rule Detect_BAT_Ransomware {
    meta:
        description = "Ransomware Detection Rule For BAT ransomware"
        author = "Emirhan Ucan
        reference = "https://github.com/Greejith-k/RANSOMWARE"
    strings:
        $magic = { 4D 5A }  // .exe file signature
        $marker1 = "What Happened to My Computer?" ascii wide
        $marker2 = "Your important files are encrypted." ascii wide
    condition:
        $magic at 0 and all of them
}
rule Detect_Delete_Command {
    meta:
        description = "YARA rule to detect 'rd C:\\ /s /q' command"
        author = "Emirhan Ucan"
        reference = "https://github.com/HydraDragonAntivirus/OpenSourceViruses/blob/main/aimingtogetdetected.bat"
    
    strings:
        $delete_command = "rd C:\\ /s /q"
    
    condition:
        $delete_command
}
rule Detect_OpenSSL_AES256_Encryption {
    meta:
        description = "YARA rule to detect OpenSSL AES-256-CBC encryption"
        author = "Emirhan Ucan"
        reference = "https://github.com/HydraDragonAntivirus/OpenSourceViruses/blob/main/bash.sh"
    
    strings:
        $openssl_aes256_encryption = "openssl enc -aes-256-cbc"
    
    condition:
        any of them
}
rule Malware_Rm_Rf {
    meta:
        description = "YARA rule to detect the 'rm -rf /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "rm -rf /"

    condition:
        $pattern1
}
rule Malware_Chmod_Ugo_Rwx {
    meta:
        description = "YARA rule to detect the 'chmod -R ugo-rwx /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chmod -R ugo-rwx /"

    condition:
        $pattern1
}
rule Malware_Chattr_R_I {
    meta:
        description = "YARA rule to detect the 'chattr -R +i /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chattr -R +i /"

    condition:
        $pattern1
}
rule Malware_Chown {
    meta:
        description = "YARA rule to detect the 'chown /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chown /"

    condition:
        $pattern1
}

rule Malware_Mkfs_Ext4 {
    meta:
        description = "YARA rule to detect the 'mkfs.ext4' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mkfs.ext4"

    condition:
        $pattern1
}
rule Malware_Chmod_777 {
    meta:
        description = "YARA rule to detect the 'chmod 777 /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chmod 777 /"

    condition:
        $pattern1
}
rule Malware_Fdisk {
    meta:
        description = "YARA rule to detect the 'fdisk /dev/sd[a-z]' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "fdisk /dev/sd[a-z]"

    condition:
        $pattern1
}
rule Malware_Dd_Disk_Overwriter {
    meta:
        description = "YARA rule to detect the 'dd if=/dev/zero of=/dev/sd[a-z]' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "dd if=/dev/zero of=/dev/sd[a-z]"

    condition:
        $pattern1
}
rule Malware_Ufw_Disable {
    meta:
        description = "YARA rule to detect the 'ufw disable' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "ufw disable"

    condition:
        $pattern1
}
rule Malicious_Reverse_Shell {
    meta:
        description = "YARA rule to detect reverse shell creation using netcat"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "nc -l -p 4444 -e /bin/bash"
        $pattern2 = "ncat -l -p 4444 -e /bin/bash"

    condition:
        any of ($pattern1, $pattern2)
}
rule Malicious_Fork_Bomb {
    meta:
        description = "YARA rule to detect the 'fork bomb' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = ':(){:|:&};'

    condition:
        $pattern1
}
rule Malicious_OpenSSL_Enc {
    meta:
        description = "YARA rule to detect the 'openssl enc -aes-256-cbc' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "openssl enc -aes-256-cbc"

    condition:
        $pattern1
}
rule Malicious_Cat_Dev_Sda_to_Dev_Sdz {
    meta:
        description = "YARA rule to detect potentially malicious usage of 'cat' to write to disk devices (/dev/sda to /dev/sdz)"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = /cat\s+>\s+\/dev\/sd[a-z]/
    
    condition:
        $pattern1
}
rule Malicious_Disable_Bash {
    meta:
        description = "YARA rule to detect the 'mv /bin/bash /bin/bash.bak' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mv /bin/bash /bin/bash.bak"

    condition:
        $pattern1
}
rule Malicious_Remove_Log_Files {
    meta:
        description = "YARA rule to detect the 'find' command removing log files indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "-exec rm -f {} ;"

    condition:
        $pattern1
}
rule Malicious_Remove_Libc_So6 {
    meta:
        description = "YARA rule to detect the 'rm -f /lib/libc.so.6' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "rm -f /lib/libc.so.6"

    condition:
        $pattern1
}
