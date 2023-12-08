# Hydra Dragon Anti-virus For Linux
# The Project Is Dead I created New Project Use Wine To Open That https://mega.nz/file/fkRjnRbZ#lqKOZU6_JSgFXZrGn_bbJjQxskJlv-QEbnHUYQQqtuk
<p align="center">
<img src="assets/logo.png" width= 200px>
</p>

## Notice
You need use Firefox as your browser
The project is dead now. I created my first very effective malware cleanner.
## Feautres
- Real-time protection
- Web protection
- SHA256-SHA1-MD5-SSDEEP-TLSH calculator
- Big databases for free. Above the 70 million virus hashes here
- ClamAV on Python
- Rootkit scanner are united in one python script
- Average daily 1k new virus hashes and 700+ new virus or phsihing websites
- Heuristical Scanning With ClamAV and YARA rules
## Download
Download full version [here](https://mega.nz/folder/n85EkQwa#6E6xSXO5Y2NQ4rzrg-nIzA)
### Read before using
- Don't forget give permission access.
- It really disconnect infected ip address and it deletes file so be careful!
- It deletes files there no quarantine option yet. I didn't added yet but in future I'm going to add them.
- Don't forget to use clamonacc
- Test the suspicous file in home folder
## Contact
<a href="https://discord.gg/W2N27aF5"><img src="https://img.shields.io/discord/72895893221067986?style=flat-square&logo=appveyor"></a>
### semaemirhan555@gmail.com
## License
Do What The F*ck You Want To Public License ![foto](https://github.com/HydraDragonAntivirus/Hydra-Dragon-Antivirus-Linux/assets/142328963/d680ca0c-6d13-41f0-91b8-d8b32e85a95a)
## How To Give Root Access To Program
sudo python Antivirus.py
## Current Statics
I have **65247054+** normal virus hashes **1596191+** virus or illegal websites and IP address list except other phishing databases and KADhosts also others 16k 3k iblocklist and dnsblocklist  **2.5 million** virus, phishing or safe website. Total fuzzy hashes
**4893048+ (800k≈ Malwarebazaar+ClamAV)** Phishing Database github **1050851** TR Phishing Database github **922180** and **4.000.00+** secureinfo.com signatures. **50.000** other unoffical free clamav database signatures and KADhosts **98083** https://linuxreviews.org/Comparison_of_HOST_file_blacklists others **16k** iblocklist **3294** dnsblocklist **1 million**opensquat**176594**
## Detection Rate
ClamAV 60% Hydra Dragon Antivirus 65%
## Collected Datas
No data collected
## Installation On Arch Linux For Beginners
### Please First Test It On Virtual Machine Antivirus Might Be Crash Your System
### Tested On Cachy OS And If You Looking For Debian Tested On Kali Linux And It Worked But Best Works At Debian Based Distros For All Features
- sudo pacman -S python
- sudo pacman -S python-appdirs
- sudo pacman -S python-tlsh
- sudo pacman -S strace
- sudo pacman -S python-pyinotify
- sudo pacman -S rkhunter
- sudo pacman -S clamav
- sudo pacman -S firejail
- sudo pacman -S python-yara
### Download This Files
- http://database.clamav.net/main.cvd
- http://database.clamav.net/daily.cvd
- If you got banned try again in 24 hours
- Save at Downloads
- cd
- cd Downloads
- git clone https://aur.archlinux.org/chkrootkit.git
- cd chkrootkit/
- makepkg -si
- Then check installation by typing sudo chkrootkit
- cd ..
- sudo cp main.cvd /var/lib/clamav/
- sudo cp daily.cvd /var/lib/clamav/
- Type sudo clamscan to check clamscan
- Installing ssdeep:
- git clone https://github.com/DinoTools/python-ssdeep.git
- cd python-ssdeep/
- sudo pacman -S python-setuptools
- sudo pacman -S python-pip
- sudo pacman -S ssdeep
- python setup.py build
- pip install sigmatools
- sudo python setup.py install
- cd ..
- sudo nano /etc/clamav/freshclam.conf
- Then paste this:
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfo.hdb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfo.ign2
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/javascript.ndb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/spam_marketing.ndb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfohtml.hdb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfoascii.hdb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfoandroid.hdb--
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfoold.hdb
- DatabaseCustomURL https://www.securiteinfo.com/get/signatures/9e46fcf748515c2e273120875878728d48c4aa222679a44eb5bbddbcd59914f4dc15ae118bd3e47a0b1e6129009ee1f31860406710c2581773be718f70f515ae/securiteinfopdf.hdb
- Then Ctrl+S then Ctrl+X then sudo freshclam
- https://blog.frehi.be/2021/01/25/using-fangfrisch-to-improve-malware-e-mail-detection-with-clamav/

- sudo freshclam
- sudo systemctl
- start clamav-daemon
- pip install tk
- Use my yara and hrfxn.db file in clamav signatures.
### Download Antivirus from mega.nz link: https://mega.nz/folder/n85EkQwa#6E6xSXO5Y2NQ4rzrg-nIzA
- Save At Downloads
- unzip Antivirus.zip
- cd Antivirus\
- Type sudo python Antivirus.py you are done
- You can also start without root by typing python Antivirus.py
- If you have a problem create issue topic or try reboot
## How To Update Databases Manually?
- https://www.youtube.com/@hydradragonantivirus Watch my videos here. It will help you or look this: 
- Hydra Dragon Antivirus  active sources: virusshare.com FossAV BatchAntivirus Abusech Steven Black Ultimatehostblacklist github https://vxug.fakedoma.in/samples/ https://www.usom.gov.tr/ malwares.com clamav.net  https://www.reddit.com/r/netsec/comments/gp1rm/list_of_malicious_domains_and_ip_blocklists/  https://winhelp2002.mvps.org/ future plans: https://www.iblocklist.com/subscribe virussign.com heuristics: https://bazaar.abuse.ch/browse.php?search=file_type%3Abat and Hypatia database maybe waiting for 10k pdf malwares.com still waiting for access https://www.youtube.com/watch?v=4U_AAtMel94 https://www.vx-underground.org/ I should add Linux malware database. non-active source example: https://justdomains.github.io/blocklists/ so big https://www.reddit.com/r/Malware/comments/7fabu5/sites_to_download_malware/ plans: I realized that I can improve my self at open source  virus detection
- and reverse engineering Currently my antivirus right now is the best open source antivirus in the world
- and  I should unite my project with clamav and improve his heuristics and I need api
- and also need check are system files deleted also use rootkit hunter also auditd detect init 0 etc. should be added is shutdown etc. runnied  realize them new active source: https://malshare.com/daily/?C=M;O=A https://github.com/phpMussel/Signatures https://github.com/mitchellkrogza/Phishing.Database/tree/master sudo freshclam with updated securiteinfo and fangfrisch https://github.com/HorusTeknoloji/TR-PhishingList archived https://github.com/FiltersHeroes/KADhosts https://linuxreviews.org/Comparison_of_HOST_file_blacklists 2 Host Blacklists Reviewed https://github.com/hagezi/dns-blocklists https://github.com/atenreiro/opensquat use this for antivirus to detect phishing. https://github.com/surajr/URL-Classification 
    2.1 2o7.net list
    2.2 AdAway default
    2.3 hpHosts
    2.4 KADhosts
    2.5 MVPS
    2.6 Steven Black's "Unified hosts file"
    2.7 Ultimate.Hosts.Blacklist
    2.8 Yoyo's Adservers
- dd if=daily.cvd of=daily.tar.gz skip=1 bs=512
- chmod -R +rw daily/
- daily: daily.hdb daily.sfp daily.msu daily.hdu daily.fp daily.mdu daily.mdb
- dailyz: daily.msb daily.hsu daily.hsb
- dailyfuzzyhashes: daily.ldb
- to remove: daily.cdb daily.cfg daily.crb daily.ftm daily.idb daily.ign daily.ign2 daily.info daily.ldu daily.ndb daily.ndu daily.pdb daily.wdb
- YARA: https://yaraify.abuse.ch/yarahub/
- -YARA: Look the Awesome YARA rules. I collected YARA rules from there and please look the web archive.
- https://github.com/ditekshen
- https://github.com/baderj/yara
- Phising Database: https://github.com/mitchellkrogza/Phishing.Database
- https://yaraify.abuse.ch/ Download YARA rules via YARAifyhub
  ## Database Comprasion
  -Kaspersky have 2 billion databases
  -Virussign 600 million
  -Virusshare 70 million but didn't shared all of them
  -Me 70 million
  -phishtank 8.5 million
  -Me 4.7 million
## TODO 
- Create requirements.txt
- Create Quarantine Option In GUI
## How To Test Antivirus?
- You can use virusshare.com but have some false positives be careful or look this:
- https://tracker.h3x.eu/download/5000
- https://www.reddit.com/r/Malware/comments/7fabu5/sites_to_download_malware/
- ## How To Improve Protection Rate Very Easily?
- The best easiest way is the writing YARA rules otherwise learn reverse engeering.
- You can use ClamAV via for that. Notice it may cause too many false positives but less false negatives and you can easily name the virus names.
- https://www.rfxn.com/projects/linux-malware-detect/ Use this thing too.
- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://www.virustotal.com/gui/file/d35eb98fe63f11d5f979a5cbad5ae6ebbb9a1e8ec3fae9db80537e153a009263?nocache=1
- Awesome YARA
- https://github.com/WithSecureLabs/lazarus-sigma-rules
- https://github.com/jatrost/awesome-detection-rules
- https://github.com/eybisi/hacky-yara-androguard/blob/master/dropper.yar
- https://github.com/BiteFoo/androyara
- https://unprotect.it/detection-rule/yara_disable_antivirus/
- https://github.com/nbs-system/php-malware-finder
