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
