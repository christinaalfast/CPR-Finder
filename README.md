<!--
Title: CPR-Finder
Description: Identifies shares and checks file content for cpr-numbers (Danish Social Security Numbers).
The search is performed based on regular expressions and can assist you in your GDPR efforts.
Modulus 11 check is performed to minimize the amount of false positives.
Authors: Christina Alfast Espensen & Benjamin Henriksen
-->


			 CCCCC  PPPPPP  RRRRRR         FFFFFFF IIIII NN   NN DDDDD   EEEEEEE RRRRRR
			CC    C PP   PP RR   RR        FF       III  NNN  NN DD  DD  EE      RR   RR
			CC      PPPPPP  RRRRRR  _____  FFFF     III  NN N NN DD   DD EEEEE   RRRRRR
			CC    C PP      RR  RR         FF       III  NN  NNN DD   DD EE      RR  RR
			 CCCCC  PP      RR   RR        FF      IIIII NN   NN DDDDDD  EEEEEEE RR   RR





## CPR-Finder
			Authors: Christina Alfast Espensen & Benjamin Henriksen

## Installation:					
To install the prerequisites for **CPR-finder**, follow the instructions below
1. Make sure you have the **Powershell Active Directory module** installed
2. **Install** [FileLocator Pro](https://www.mythicsoft.com/filelocatorpro/). We have no affiliation with Mythicsoft
3. **Start** FileLocator Pro once to allow command line execution. Select trail license, unless you have a key. Do **not** select lite
4. **Close** FileLocator Pro


You are now ready to run CPR-Finder.ps1. We recommend running the script with a newly created user account with no specific or privileged access rights if you want to locate files with “unprotected” cpr-numbers.
If your objective is to identify every file with cpr-numbers in them, you can scan using a privileged account which has read access to all your data.

To scan all fixed drives on localhost run:

		CPR-Finder.ps1

To scan all servers in your domain run:

		CPR-Finder.ps1 -ScanMode ServersOnly
Refer to the examples for further details.	


## Usage
Identifies shares and checks file content for cpr-numbers (Danish Social Security Numbers).
The search is performed based on regular expressions and can assist you in your GDPR efforts.
   Modulus 11 check is performed to minimize the amount of false positives.
Dates where modulus 11 is not upheld are excluded.
This tool will allow you to scan your environment. The tool is not meant as a substitute
for a commercial enterprise solution if that is what you require.
### Modes
CPR-Finder can run in three  modes:

**1. Host-Only Mode** (Default)

        CPR-Finder Host-Only Mode consists of the following three phases:

        Phase 1: Identify local fixed drives or supplied paths.

        Phase 2: The identified local fixed drives or supplied paths are scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.                 

        Phase 3: Parse output to html file and csv file

**2. Domain Mode** - All hosts

        CPR-Finder Domain Mode consists of the following three phases:

        Phase 1: Identify open shares found on the Active Directory hosts in your environment
                 by utilizing Invoke-ShareFinder by harmjoy.

        Phase 2: The identified open shares are then scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.  

        Phase 3: Parse output to html file and csv file

**3. Domain Mode** - Servers only

        CPR-Finder Domain Mode consists of the following three phases:

        Phase 1: Identify open shares found on the Active Directory servers in your environment
                 by utilizing Invoke-ShareFinder by harmjoy.

        Phase 2: The identified open shares are then scanned for files with CPR numbers
                 by utilizing the commercial tool Filelocator Pro, which is developed by Mythicsoft.  

        Phase 3: Parse output to html file and csv file


## Parameters
**ComputerPasswordAgeDays**
	    Only applicable to Domain Mode.
		Specifies the amount of days since the computer has changed password.
	    This is an indicator of whether or not a computer object in Active Directory is dead or alive.
	    The default and recommend value is 31. We recommend using this value.

**StartGui**
	You can choose to start the GUI of FileLocator Pro. When you do this, the output will **not** be parsed and no new html or csv file is generated.
    This should be used for **debug purposes only**.

 **ScanMode**
    All: When this value is selected the scan will be performed on all hosts in the domain (default search base).
    HostOnly: (Default) Will only scan drives or supplied paths. (Accepts UNC paths).
    ServerOnly: When this parameter is supplied the scan will only be performed on Windows servers and none Windows devices i.e. NAS devices (only those with shares will be scanned).

**ScanTarget**
    Not applicable for Domain Mode.
    Supply a semi colon (;) separated list of drives to scan. See example.

**ScanAllFiles**
    Sets the file types to scan to all files.
    Default is Document type files.
    Scaning all file types will increas the scanning time, and increase the number of false positives.

**IncludeCPRInOutput**
    This will include the first found (and modulus matched) CPR number in the parsed output files.

## Examples
Find files with CPR numbers in c:\temp and "c:\temp folder":

	    CPR-Finder.ps1 -ScanTarget "C:\Temp;C:\Temp Folder"
    
Finds files with CPR numbers on the share \\pluto\users, and includes CPR-numbers in the output file.

		CPR-Finder.ps1 -ScanTarget "\\pluto\users" -IncludeCPRInOutput

Scans shares in the entire domain.

		CPR-Finder.ps1 -ScanMode All

Scans all fixed drives on localhost, this is default.

		CPR-Finder.ps1 -ScanMode HostOnly

Scans all file types on all fixed drives on localhost. Setting ScanAllFiles will increase the scan time and is normally not recommended.

		CPR-Finder.ps1 -ScanMode HostOnly -ScanAllFiles

Scan shares on all servers in the domain, where the computer account has changed password within the
last 5 days. CPR-numbers are **included** in the output.
ComputerPasswordAgeDays can be used for **testing** purposes:

		CPR-Finder.ps1 -ScanMode ServersOnly -ComputerPasswordAgeDays 5 -IncludeCPRInOutput

Loads FileLocator Pro, with all fixed drives as targets, press start to start the scan. The scanresult
will not be parsed.  This is for **testing** only:

	    CPR-Finder.ps1 -StartGui

## Credentials
The credentials used to run the script, will determine which files are accessible (scanned) - so choose these credentials wisely.	 
If you are only interested in CPR-numbers that are readable to "everyone", create a "random" user account, and run the script with that user.
We recommend using a none privileged account during the first scans, to ensure that unprotected files are addressed initially.
For performance reasons the scan moves on to another file after 50 CPR-Number hits. Modulus confirmation stops after one CPR-number verification.
## Known "issues"
 When handling compressed archives (.zip, .pst and .ost files) every file with cpr-numbers
 within the archive is flagged. This means a .pst file with 100 e-mails containing
 cpr-numbers will be flagged 100 times. This will allow you to locate the excat e-mails
 getting flagged. The output for compressed archives not mentioned above, is stil being improved.
 
## Version & License
Version 1.42
Release date: 30-09-2019
License: BSD 3-Clause
A very slightly modified version of harmj0y’s invoke-sharefinder is embedded.



## Modulus 11
The following dates are dates CPR numbers without modulus 11 control has been issued:

		1. januar 1960	1. januar 1964	1. januar 1965	1. januar 1966
		1. januar 1969	1. januar 1970	1. januar 1980	1. januar 1982
		1. januar 1984	1. januar 1985	1. januar 1986	1. januar 1987
		1. januar 1988	1. januar 1989	1. januar 1990	1. januar 1992

    https://cpr.dk/cpr-systemet/personnumre-uden-kontrolciffer-modulus-11-kontrol/
