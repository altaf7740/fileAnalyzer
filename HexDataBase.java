package fileAnalyzer;
public class HexDataBase {
    public String fileExtention, fileInformation;

    public void getfileInformation(String hex){

        for(boolean flag = false; flag != true; hex = hex.substring(0, hex.length()-3)){
            if(hex.length()<3)
                break;
            switch(hex){
                case    "41 43 53 44":  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "AOL parameter|info files"; 
                                    flag = true; 
                                    break;
                case    "62 70 6C 69 73 74":  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "Binary property list (plist)"; 
                                    flag = true; 
                                    break;
                case    "00 14 00 00 01 02" 	    :  
                                    fileExtention =      "unknown"     ;
                                    fileInformation = "BIOS details in RAM"; 
                                    flag = true; 
                                    break;
                case    "30 37 30 37 30" 	        :  
                                    fileExtention =      "unknown"     ;
                                     fileInformation = "cpio archive"; 
                                     flag = true; 
                                     break;
                case    "7F 45 4C 46" 	            :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "ELF executable"; 
                                    flag = true; 
                                    break;
                case    "A1 B2 CD 34" 	            :  
                                    fileExtention =      "unknown"     ;
                                    fileInformation = "Extended tcpdump (libpcap) capture file";
                                    flag = true; break;
                case    "04 00 00 00" 	            :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "INFO2 Windows recycle bin_1";
                                    flag = true;
                                    break;
                case    "05 00 00 00" 	            : 
                                    fileExtention =      "unknown"     ;
                                     fileInformation = "INFO2 Windows recycle bin_2"; 
                                     flag = true;
                                      break;
                case    "AC ED" 	                :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "Java serialization data"; 
                                    flag = true; 
                                    break;
                case    "4B 57 41 4A 88 F0 27 D1"  :	
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "KWAJ (compressed) file"; 
                                    flag = true; 
                                    break;
                case    "CD 20 AA AA 02 00 00 00"  :	
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "NAV quarantined virus file"; 
                                    flag = true; 
                                    break;
                case    "53 5A 20 88 F0 27 33 D1"  :	
                                    fileExtention =      "unknown"     ;
                                     fileInformation = "QBASIC SZDD file";
                                      flag = true; 
                                      break;
                case    "6F 3C"                     :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "SMS text (SIM)"; 
                                    flag = true; 
                                    break;
                case    "53 5A 44 44 88 F0 27 33"  :	
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "SZDD file format"; 
                                    flag = true; 
                                    break;
                case    "A1 B2 C3 D4"               :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "tcpdump (libpcap) capture file"; 
                                    flag = true; 
                                    break;
                case    "34 CD B2 A1"               :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "Tcpdump capture file"; 
                                    flag = true; 
                                    break;
                case    "EF BB BF"                  :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "UTF8 file"; 
                                    flag = true; 
                                    break;
                case    "FE FF"                     :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "UTF-16|UCS-2 file"; 
                                    flag = true; 
                                    break;
                case    "FF FE 00 00"               :  
                                    fileExtention =      "unknown"     ;
                                     fileInformation = "UTF-32|UCS-4 file"; 
                                     flag = true;
                                      break;
                case    "62 65 67 69 6E"            :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "UUencoded file";
                                     flag = true;
                                      break;
                case    "D4 C3 B2 A1"               :  
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "WinDump (winpcap) capture file"; 
                                    flag = true;
                                     break;
                case    "37 E4 53 96 C9 DB D6 07"  :	
                                    fileExtention =      "unknown"     ; 
                                    fileInformation = "zisofs compressed file";
                                     flag = true; 
                                     break;
                case 	"4D 5A"                     :  
                                    fileExtention =      ".VXD, .VBX, .SYS, .QTS, .QTX, .PIF, .OLB, .OCX, .386, .ACM, .AX, .COM, .CPL, .DLL .DRV .EXE, .FON "     ; fileInformation = "Windows virtual device drivers, VisualBASIC application || OLE object library ||ActiveX|OLE Custom Control || Font file || Control panel application || Windows|DOS executable file || Library cache file || MS audio compression manager driver || Windows virtual device drivers "; flag = true; break;
                case 	"00 00 00 14 66 74 79 70"  :	
                                    fileExtention =          "3GP"     ;
                                     fileInformation = "3GPP multimedia files";
                                      flag = true; 
                                      break;
                case 	"00 00 1A 00 05 10 04"      :  
                                    fileExtention =          "123"     ;
                                     fileInformation = "Lotus 1-2-3 (v9)"; 
                                     flag = true;
                                      break;
                case 	"00 00 00 20 66 74 79 70"  :	
                                    fileExtention =          ".M4A, 3GP"     ; 
                                    fileInformation = "Apple audio and video files || 3GPP2 multimedia files"; 
                                    flag = true; 
                                    break;
                case 	"00 00 00 18 66 74 79 70"  :	
                                    fileExtention =          "3GPS, .MP4"    ; fileInformation = "MPEG-4 video files"; flag = true; break;
                case 	"52 49 46 46"               :  
                                    fileExtention =          ".WAV, .RMI, .QCP, .DSY, .DAT, .CMX, .CRD, .CDA, .AVI, .ANI, .4XM"     ; fileInformation = "Micrografx Designer graphic || Video CD MPEG movie || Corel Presentation Exchange metadata || CorelDraw document, Resource Interchange File Format || Windows animated cursor || 4X Movie video"; flag = true; break;
                case 	"37 7A BC AF 27 1C"         :  
                                    fileExtention =          "7Z"      ; fileInformation = "7-Zip compressed file"; flag = true; break;
                case 	"00 01 42 41"               :  
                                    fileExtention =          "ABA"     ; fileInformation = "Palm Address Book Archive"; flag = true; break;
                case 	"51 57 20 56 65 72 2E 20"  :	
                                    fileExtention =          ".QSD, .ABD"     ; fileInformation = "ABD | QSD Quicken data file"; flag = true; break;
                case 	"41 4F 4C 49 4E 44 45 58"  :	
                                    fileExtention =          "ABI"     ; fileInformation = "AOL address book index"; flag = true; break;
                case 	"41 4F 4C"                  :  
                                    fileExtention =          "ABI or ABY or or IDX or BAG or IND or PFC"     ; fileInformation = "AOL config files"; flag = true; break;
                case 	"41 4F 4C 44 42"            :  
                                    fileExtention =          ".IDX,.ABY"     ; fileInformation = "AOL user configuration || AOL address book"; flag = true; break;
                case	"72 69 66 66"               :  
                                    fileExtention =          "AC"      ; fileInformation = "Sonic Foundr y Acid Music File"; flag = true; break;
                case 	"00 01 00 00 53 74 61 6E"   :  
                                    fileExtention =          ".MDB, .ACCDB"   ; fileInformation = "Microsoft Access 2007"; flag = true; break;
                case 	"C3 AB CD AB"               :  
                                    fileExtention =          "ACS"     ; fileInformation = "MS Agent Character file"; flag = true; break;
                case 	"D0 CF 11 E0 A1 B1 1A E1"  :	
                                    fileExtention =          ".VSD, .WIZ, .WPS, .XLA, .XLS, .OPT,  .PPS, .PPT,  .PUB, .RVT, .SOU, .SPO,  .MTW, .MSI, .MSC, .DOT, .DOC, .DB, .APR, .ADP, .AC_"; fileInformation = "Visio file || Microsoft Office document || MSWorks text document || Developer Studio File Options file || Microsoft Office document || Microsoft Office document || MS Publisher file || Revit Project file || Visual Studio Solution User Options file || SPSS output file || SPSS output file || Minitab data file || Microsoft Installer package, Microsoft Common Console Document ||Microsoft Office document, Microsoft Office document || MSWorks database file || Lotus|IBM Approach 97 file || Access project file || CaseWare Working Papers"; flag = true; break;
                case	"52 45 56 4E 55 4D 3A 2C"  :	
                                    fileExtention =          "AD"      ; fileInformation = "Antenna data file"; flag = true; break;
                case 	"44 4F 53"                  :  
                                    fileExtention =          "ADF"     ; fileInformation = "Amiga disk file"; flag = true; break;
                case 	"03 00 00 00 41 50 50 52"  :	
                                    fileExtention =          "ADX"     ; fileInformation = "Approach index file"; flag = true; break;
                case 	"80 00 00 20 03 12 04"      :  
                                    fileExtention =          "ADX"     ; fileInformation = "Dreamcast audio"; flag = true; break;
                case 	"46 4F 52 4D 00"            :  
                                    fileExtention =          "AIFF"    ; fileInformation = "Audio Interchange File"; flag = true; break;
                case 	"21 12"                     :  
                                    fileExtention =          "AIN"     ; fileInformation = "AIN Compressed Archive"; flag = true; break;
                case 	"23 21 41 4D 52"            :  
                                    fileExtention =          "AMR"     ; fileInformation = "Adaptive Multi-Rate ACELP Codec (GSM)"; flag = true; break;
                case 	"4D 5A 90 00 03 00 00 00"  :	
                                    fileExtention =          ".ZAP, .FLT, .AX, .API, .EXE, .DLL"     ; fileInformation = "ZoneAlam data file || Audition graphic filter || DirectShow filter || Acrobat plug-in"; flag = true; break;
                case 	"41 72 43 01"               :  
                                    fileExtention =          "ARC"     ; fileInformation = "FreeArc compressed file"; flag = true; break;
                case 	"1A 02"                     :  
                                    fileExtention =          "ARC"     ; fileInformation = "LH archive (old vers.|type 1)"; flag = true; break;
                case 	"1A 03"                     :  
                                    fileExtention =          "ARC"     ; fileInformation = "LH archive (old vers.|type 2)"; flag = true; break;
                case 	"1A 04"                     :  
                                    fileExtention =          "ARC"     ; fileInformation = "LH archive (old vers.|type 3)"; flag = true; break;
                case 	"1A 08"                     :  
                                    fileExtention =          "ARC"     ; fileInformation = "LH archive (old vers.|type 4)"; flag = true; break;
                case 	"1A 09"                     :  
                                    fileExtention =          "ARC"     ; fileInformation = "LH archive (old vers.|type 5)"; flag = true; break;
                case 	"60 EA"                     :  
                                    fileExtention =          "ARJ"     ; fileInformation = "ARJ Compressed archive file"; flag = true; break;
                case 	"D4 2A"                     :  
                                    fileExtention =          ".ARL, .AUT"     ; fileInformation = "AOL history|typed URL files"; flag = true; break;
                case 	"30 26 B2 75 8E 66 CF 11"   :  
                                    fileExtention =          ".WMA, .WMF, .ASF"     ; fileInformation = "Windows Media Audio|Video File"; flag = true; break;
                case 	"53 43 48 6C"               :  
                                    fileExtention =          "AST"     ; fileInformation = "Underground Audio"; flag = true; break;
                case 	"3C"                        :  
                                    fileExtention =          ".XDR, .ASX"     ; fileInformation = "BizTalk XML-Data Reduced Schema || Advanced Stream Redirector"; flag = true; break;
                case	"64 6E 73 2E"              :	
                                    fileExtention =          "AU"      ; fileInformation = "Audacity audio file"; flag = true; break;
                case	"2E 73 6E 64"              :	
                                    fileExtention =          "AU"      ; fileInformation = "NeXT|Sun Microsystems audio file"; flag = true; break;
                case	"8A 01 09 00 00 00 E1 08"   :  
                                    fileExtention =          "AW"      ; fileInformation = "MS Answer Wizard"; flag = true; break;
                case 	"41 4F 4C 20 46 65 65 64"  :	
                                    fileExtention =          "BAG"     ; fileInformation = "AOL and AIM buddy list"; flag = true; break;
                case 	"58 54"                     :  
                                    fileExtention =          "BDR"     ; fileInformation = "MS Publisher"; flag = true; break;
                case 	"42 4C 49 32 32 33 51"      :  
                                    fileExtention =          "BIN"     ; fileInformation = "Speedtouch router firmware"; flag = true; break;
                case 	"42 4D"                     :  
                                    fileExtention =          ".DIB, .BMP"     ; fileInformation = "Bitmap image"; flag = true; break;
                case 	"42 5A 68"                  :  
                                    fileExtention =          ".TB2, .TBZ2, .TAR.BZ2, .BZ2"     ; fileInformation = "bzip2 compressed archive"; flag = true; break;
                case 	"4D 53 43 46"               :  
                                    fileExtention =          ".SNP, .PRZ, .CAB"     ; fileInformation = "MS Access Snapshot Viewer file || Powerpoint Packaged Presentation || Microsoft cabinet file"; flag = true; break;
                case 	"73 72 63 64 6F 63 69 64"  :	
                                    fileExtention =          "CAL"     ; fileInformation = "CALS raster bitmap"; flag = true; break;
                case 	"53 75 70 65 72 43 61 6C"  :	
                                    fileExtention =          "CAL"     ; fileInformation = "SuperCalc worksheet"; flag = true; break;
                case 	"B5 A2 B0 B3 B3 B0 A5 B5"  :	
                                    fileExtention =          "CAL"     ; fileInformation = "Windows calendar"; flag = true; break;
                case 	"58 43 50 00"               :  
                                    fileExtention =          "CAP"     ; fileInformation = "Packet sniffer files"; flag = true; break;
                case 	"52 54 53 53"               :  
                                    fileExtention =          "CAP"     ; fileInformation = "WinNT Netmon capture file"; flag = true; break;
                case 	"5F 43 41 53 45 5F"         :  
                                    fileExtention =          ".CBK, .CAS"     ; fileInformation = "EnCase case file || EnCase case file"; flag = true; break;
                case 	"30"                        :  
                                    fileExtention =          "CAT"     ; fileInformation = "MS security catalog file"; flag = true; break;
                case 	"43 42 46 49 4C 45"         :  
                                    fileExtention =          "CBD"     ; fileInformation = "WordPerfect dictionary"; flag = true; break;
                case 	"45 4C 49 54 45 20 43 6F"  :	
                                    fileExtention =          "CDR"     ; fileInformation = "Elite Plus Commander game file"; flag = true; break;
                case 	"4D 53 5F 56 4F 49 43 45"  :	
                                    fileExtention =          ".MSV, .DVF, .CDR"     ; fileInformation = "Sony Compressed Voice File"; flag = true; break;
                case 	"5B 66 6C 74 73 69 6D 2E"  :	
                                    fileExtention =          "CFG"     ; fileInformation = "Flight Simulator Aircraft Configuration"; flag = true; break;
                case 	"49 54 53 46"               :  
                                    fileExtention =          ".CHM, ,CHI"     ; fileInformation = "MS Compiled HTML Help File"; flag = true; break;
                case 	"CA FE BA BE"               :  
                                    fileExtention =          "CLASS"   ; fileInformation = "Java bytecode"; flag = true; break;
                case 	"43 4F 4D 2B"               :  
                                    fileExtention =          "CLB"     ; fileInformation = "COM+ Catalog"; flag = true; break;
                case 	"43 4D 58 31"               :  
                                    fileExtention =          "CLB"     ; fileInformation = "Corel Binary metafile"; flag = true; break;
                case 	"53 51 4C 4F 43 4F 4E 56"  :	
                                    fileExtention =          "CNV"     ; fileInformation = "DB2 conversion file"; flag = true; break;
                case 	"4E 61 6D 65 3A 20"         :  
                                    fileExtention =          "COD"     ; fileInformation = "Agent newsreader character map"; flag = true; break;
                case 	"E8"                        :  
                                    fileExtention =          ".SYS, .COM"     ; fileInformation = "Windows executable file_1"; flag = true; break;
                case 	"E9"                        :  
                                    fileExtention =          ".SYS, .COM"     ; fileInformation = "Windows executable file_2"; flag = true; break;
                case 	"EB"                        :  
                                    fileExtention =          ".SYS, .COM"     ; fileInformation = "Windows executable file_3"; flag = true; break;
                case 	"46 41 58 43 4F 56 45 52"  :	
                                    fileExtention =          "CPE"     ; fileInformation = "MS Fax Cover Sheet"; flag = true; break;
                case 	"53 49 45 54 52 4F 4E 49"  :	
                                    fileExtention =          "CPI"     ; fileInformation = "Sietronics CPI XRD document"; flag = true; break;
                case 	"FF 46 4F 4E 54"            :  
                                    fileExtention =          "CPI"     ; fileInformation = "Windows international code page"; flag = true; break;
                case 	"DC DC"                     :  
                                    fileExtention =          "CPL"     ; fileInformation = "Corel color palette"; flag = true; break;
                case 	"43 50 54 37 46 49 4C 45"  :	
                                    fileExtention =          "CPT"     ; fileInformation = "Corel Photopaint file_1"; flag = true; break;
                case 	"43 50 54 46 49 4C 45"      :  
                                    fileExtention =          "CPT"     ; fileInformation = "Corel Photopaint file_2"; flag = true; break;
                case 	"5B 57 69 6E 64 6F 77 73"  :	
                                    fileExtention =          "CPX"     ; fileInformation = "Microsoft Code Page Translation file"; flag = true; break;
                case 	"43 52 55 53 48 20 76"      :  
                                    fileExtention =          "CRU"     ; fileInformation = "Crush compressed archive"; flag = true; break;
                case 	"49 49 1A 00 00 00 48 45"  :	
                                    fileExtention =          "CRW"     ; fileInformation = "Canon RAW file"; flag = true; break;
                case 	"63 75 73 68 00 00 00 02"  :	
                                    fileExtention =          "CSH"     ; fileInformation = "Photoshop Custom Shape"; flag = true; break;
                case 	"43 61 74 61 6C 6F 67 20"  :	
                                    fileExtention =          "CTF"     ; fileInformation = "WhereIsIt Catalog"; flag = true; break;
                case 	"56 45 52 53 49 4F 4E 20"  :	
                                    fileExtention =          "CTL"     ; fileInformation = "Visual Basic User-defined Control file"; flag = true; break;
                case 	"50 4B 03 04"               :  
                                    fileExtention =          ".CUIX, .DOCX, .JAR,  .KWD,  .ODP,  .ODT,  .OTT,  .PPTX, .SXC,  .SXD,  .SXI,  .SXW,  .WMZ,  .XLSX, .XPI, .XPS, .XPT, .ZIP"    ; fileInformation = " Java archive_1 ||  KWord document || OpenDocument template ||  OpenDocument template ||  OpenDocument template ||  MS Office Open XML Format Document || StarOffice spreadsheet || OpenOffice documents || OpenOffice documents || OpenOffice documents || Windows Media compressed skin file || MS Office Open XML Format Document | Mozilla Browser Archive | XML paper specification file || eXact Packager Models | PKZIP archive_1"; flag = true; break;
                case 	"00 00 02 00"               :  
                                    fileExtention =          ".WB2, .CUR"     ; fileInformation = "QuattroPro spreadsheet, Windows cursor"; flag = true; break;
                case 	"A9 0D 00 00 00 00 00 00"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "Access Data FTK evidence"; flag = true; break;
                case 	"73 6C 68 21"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "Allegro Generic Packfile (compressed)"; flag = true; break;
                case 	"73 6C 68 2E"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "Allegro Generic Packfile (uncompressed)"; flag = true; break;
                case 	"41 56 47 36 5F 49 6E 74"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "AVG6 Integrity database"; flag = true; break;
                case 	"03"                        :  
                                    fileExtention =       	  ".DB3, .DAT"     ; fileInformation = "dBASE III file || MapInfo Native Data Format"; flag = true; break;
                case 	"45 52 46 53 53 41 56 45"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "EasyRecovery Saved State file"; flag = true; break;
                case 	"43 6C 69 65 6E 74 20 55"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "IE History file"; flag = true; break;
                case 	"49 6E 6E 6F 20 53 65 74"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "Inno Setup Uninstall Log"; flag = true; break;
                case 	"50 4E 43 49 55 4E 44 4F"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "Norton Disk Doctor undo file"; flag = true; break;
                case 	"50 45 53 54"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "PestPatrol data|scan strings"; flag = true; break;
                case 	"1A 52 54 53 20 43 4F 4D"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "Runtime Software disk image"; flag = true; break;
                case 	"52 41 5A 41 54 44 42 31"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "Shareaza (P2P) thumbnail"; flag = true; break;
                case 	"4E 41 56 54 52 41 46 46"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "TomTom traffic data"; flag = true; break;
                case 	"55 46 4F 4F 72 62 69 74"  :	
                                    fileExtention =          "DAT"     ; fileInformation = "UFO Capture map file"; flag = true; break;
                case 	"57 4D 4D 50"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "Walkman MP3 file"; flag = true; break;
                case 	"43 52 45 47"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "Win9x registry hive"; flag = true; break;
                case 	"72 65 67 66"               :  
                                    fileExtention =          "DAT"     ; fileInformation = "WinNT registry file"; flag = true; break;
                case	"08"                        :  
                                    fileExtention =          "DB"      ; fileInformation = "dBASE IV or dBFast configuration file"; flag = true; break;
                case	"00 06 15 61 00 00 00 02"   :  
                                    fileExtention =          "DB"      ; fileInformation = "Netscape Navigator (v4) database"; flag = true; break;
                case	"44 42 46 48"               :  
                                    fileExtention =          "DB"      ; fileInformation = "Palm Zire photo database"; flag = true; break;
                case	"53 51 4C 69 74 65 20 66"   :  
                                    fileExtention =          "DB"      ; fileInformation = "SQLite database file"; flag = true; break;
                case	"FD FF FF FF"               :  
                                    fileExtention =          "DB"      ; fileInformation = "Thumbs.db subheader"; flag = true; break;
                case 	"04"                        :  
                                    fileExtention =          "DB4"     ; fileInformation = "dBASE IV file"; flag = true; break;
                case 	"00 01 42 44"               :  
                                    fileExtention =          "DBA"     ; fileInformation = "Palm DateBook Archive"; flag = true; break;
                case 	"6C 33 33 6C"               :  
                                    fileExtention =          "DBB"     ; fileInformation = "Skype user data file"; flag = true; break;
                case 	"4F 50 4C 44 61 74 61 62"  :	
                                    fileExtention =          "DBF"     ; fileInformation = "Psion Series 3 Database"; flag = true; break;
                case 	"CF AD 12 FE"               :  
                                    fileExtention =          "DBX"     ; fileInformation = "Outlook Express e-mail folder"; flag = true; break;
                case 	"3C 21 64 6F 63 74 79 70"  :	
                                    fileExtention =          "DCI"     ; fileInformation = "AOL HTML mail"; flag = true; break;
                case 	"B1 68 DE 3A"               :  
                                    fileExtention =          "DCX"     ; fileInformation = "PCX bitmap"; flag = true; break;
                case 	"64 65 78 0A 30 30 39 00"  :	
                                    fileExtention =          "dex"     ; fileInformation = "Dalvik (Android) executable file"; flag = true; break;
                case 	"78"                        :  
                                    fileExtention =          "DMG"     ; fileInformation = "MacOS X image file"; flag = true; break;
                case 	"50 41 47 45 44 55"         :  
                                    fileExtention =          "DMP"     ; fileInformation = "Windows memory dump"; flag = true; break;
                case 	"44 4D 53 21"               :  
                                    fileExtention =          "DMS"     ; fileInformation = "Amiga DiskMasher compressed archive"; flag = true; break;
                case 	"0D 44 4F 43"               :  
                                    fileExtention =          "DOC"     ; fileInformation = "DeskMate Document"; flag = true; break;
                case 	"CF 11 E0 A1 B1 1A E1 00"  :	
                                    fileExtention =          "DOC"     ; fileInformation = "Perfect Office document"; flag = true; break;
                case 	"DB A5 2D 00"               :  
                                    fileExtention =          "DOC"     ; fileInformation = "Word 2.0 file"; flag = true; break;
                case 	"EC A5 C1 00"               :  
                                    fileExtention =          "DOC"     ; fileInformation = "Word document subheader"; flag = true; break;
                case 	"50 4B 03 04 14 00 06 00"  :	
                                    fileExtention =          ".XLSX, .PPTX, .DOCX"    ; fileInformation = "MS Office 2007 documents || MS Office 2007 documents"; flag = true; break;
                case 	"07"                        :  
                                    fileExtention =          "DRW"     ; fileInformation = "Generic drawing programs"; flag = true; break;
                case 	"01 FF 02 04 03 02"         :  
                                    fileExtention =  	      "DRW"     ; fileInformation = "Micrografx vector graphic file"; flag = true; break;
                case 	"4D 56 	CD"                 :  
                                    fileExtention =          "DSN"     ; fileInformation = "Stomper Pro label file"; flag = true; break;
                case 	"23 20 4D 69 63 72 6F 73"  :	
                                    fileExtention =          "DSP"     ; fileInformation = "MS Developer Studio project file"; flag = true; break;
                case 	"02 64 73 73"               :  
                                    fileExtention =          "DSS"     ; fileInformation = "Digital Speech Standard file"; flag = true; break;
                case 	"64 73 77 66 69 6C 65"      :  
                                    fileExtention =          "DSW"     ; fileInformation = "MS Visual Studio workspace file"; flag = true; break;
                case 	"07 64 74 32 64 64 74 64"  :	
                                    fileExtention =          "DTD"     ; fileInformation = "DesignTools 2D Design file"; flag = true; break;
                case 	"5B 50 68 6F 6E 65 5D"      :  
                                    fileExtention =          "DUN"     ; fileInformation = "Dial-up networking file"; flag = true; break;
                case 	"44 56 44"                  :  
                                    fileExtention =          ".IFO, .DVR"     ; fileInformation = "DVD info file || DVR-Studio stream file"; flag = true; break;
                case 	"4F 7B"                     :  
                                    fileExtention =          "DW4"     ; fileInformation = "Visio|DisplayWrite 4 text file"; flag = true; break;
                case 	"41 43 31 30"               :  
                                    fileExtention =          "DWG"     ; fileInformation = "Generic AutoCAD drawing"; flag = true; break;
                case 	"45 56 46 09 0D 0A FF 00"  :	
                                    fileExtention =          "E01"     ; fileInformation = "Expert Witness Compression Format"; flag = true; break;
                case 	"4C 56 46 09 0D 0A FF 00"  :	
                                    fileExtention =          "E01"     ; fileInformation = "Logical File Evidence Format"; flag = true; break;
                case 	"5B 47 65 6E 65 72 61 6C"  :	
                                    fileExtention =          "ECF"     ; fileInformation = "MS Exchange configuration file"; flag = true; break;
                case 	"DC FE"                     :  
                                    fileExtention =          "EFX"     ; fileInformation = "eFax file"; flag = true; break;
                case 	"58 2D"                     :  
                                    fileExtention =          "EML"     ; fileInformation = "Exchange e-mail"; flag = true; break;
                case 	"52 65 74 75 72 6E 2D 50"  :	
                                    fileExtention =          "EML"     ; fileInformation = "Generic e-mail_1"; flag = true; break;
                case 	"46 72 6F 6D"               :  
                                    fileExtention =          "EML"     ; fileInformation = "Generic e-mail_2"; flag = true; break;
                case 	"40 40 40 20 00 00 40 40"   :  
                                    fileExtention = 	      "ENL"     ; fileInformation = "EndNote Library File"; flag = true; break;
                case 	"C5 D0 D3 C6"               :  
                                    fileExtention =          "EPS"     ; fileInformation = "Adobe encapsulated PostScript"; flag = true; break;
                case 	"25 21 50 53 2D 41 64 6F"  :	
                                    fileExtention =          "EPS"     ; fileInformation = "Encapsulated PostScript file"; flag = true; break;
                case 	"1A 35 01 00"               :  
                                    fileExtention =          "ETH"     ; fileInformation = "WinPharoah capture file"; flag = true; break;
                case 	"30 00 00 00 4C 66 4C 65"  :	
                                    fileExtention =          "EVT"     ; fileInformation = "Windows Event Viewer file"; flag = true; break;
                case 	"45 6C 66 46 69 6C 65 00"  :	
                                    fileExtention =          "EVTX"    ; fileInformation = "Windows Vista event log"; flag = true; break;
                case 	"25 50 44 46"               :  
                                    fileExtention =          ".PDF, .FDF"     ; fileInformation = "PDF file"; flag = true; break;
                case 	"66 4C 61 43 00 00 00 22"  :	
                                    fileExtention =          "FLAC"    ; fileInformation = "Free Lossless Audio Codec file"; flag = true; break;
                case 	"00 11"                     :  
                                    fileExtention =          "FLI"     ; fileInformation = "FLIC animation"; flag = true; break;
                case 	"76 32 30 30 33 2E 31 30"  :	
                                    fileExtention =          "FLT"     ; fileInformation = "Qimage filter"; flag = true; break;
                case 	"46 4C 56"                  :  
                                    fileExtention =          "FLV"     ; fileInformation = "Flash video file"; flag = true; break;
                case	"3C 4D 61 6B 65 72 46 69"  :	
                                    fileExtention =          ".MIF, .FM"      ; fileInformation = "Adobe FrameMaker"; flag = true; break;
                case 	"D2 0A 00 00"               :  
                                    fileExtention =          "FTR"     ; fileInformation = "WinPharoah filter file"; flag = true; break;
                case 	"FE EF"                     :  
                                    fileExtention =          ".GHS, .GHO"     ; fileInformation = "Symantex Ghost image file"; flag = true; break;
                case 	"3F 5F 03 00"               :  
                                    fileExtention =          ".HLP, .GID"     ; fileInformation = "Windows Help file_2"; flag = true; break;
                case 	"4C 4E 02 00"               :  
                                    fileExtention =          ".HLP, .GID"     ; fileInformation = "Windows help file_3"; flag = true; break;
                case 	"47 49 46 38"               :  
                                    fileExtention =          "GIF"     ; fileInformation = "GIF file"; flag = true; break;
                case 	"99"                        :  
                                    fileExtention =          "GPG"     ; fileInformation = "GPG public keyring"; flag = true; break;
                case 	"50 4D 43 43"               :  
                                    fileExtention =          "GRP"     ; fileInformation = "Windows Program Manager group file"; flag = true; break;
                case 	"47 58 32"                  :  
                                    fileExtention =          "GX2"     ; fileInformation = "Show Partner graphics file"; flag = true; break;
                case	"1F 8B 08"                  :  
                                    fileExtention =          "GZ"      ; fileInformation = "GZIP archive file"; flag = true; break;
                case 	"91 33 48 46"               :  
                                    fileExtention =          "HAP"     ; fileInformation = "Hamarsoft compressed archive"; flag = true; break;
                case 	"4D 44 4D 50 93 A7"         :  
                                    fileExtention =          ".DMP, .HDMP"    ; fileInformation = "Windows dump file"; flag = true; break;
                case 	"49 53 63 28"               :  
                                    fileExtention =          ".CAB, .HDR"     ; fileInformation = "Install Shield compressed file"; flag = true; break;
                case 	"23 3F 52 41 44 49 41 4E"  :	
                                    fileExtention =          "HDR"     ; fileInformation = "Radiance High Dynamic Range image file"; flag = true; break;
                case 	"48 69 50 21"               :  
                                    fileExtention =          "hip"     ; fileInformation = "Houdini image file. Three-dimensional modeling and animation"; flag = true; break;
                case 	"00 00 FF FF FF FF"         :  
                                    fileExtention =          "HLP"     ; fileInformation = "Windows Help file_1"; flag = true; break;
                case 	"28 54 68 69 73 20 66 69"  :	
                                    fileExtention =          "HQX"     ; fileInformation = "BinHex 4 Compressed Archive"; flag = true; break;
                case 	"00 00 01 00"               :  
                                    fileExtention =          ".SPL, .ICO"     ; fileInformation = "Windows icon|printer spool file"; flag = true; break;
                case 	"50 00 00 00 20 00 00 00"  :	
                                    fileExtention =          "IDX"     ; fileInformation = "Quicken QuickFinder Information File"; flag = true; break;
                case 	"50 49 43 54 00 08"         :  
                                    fileExtention =          "IMG"     ; fileInformation = "ChromaGraph Graphics Card Bitmap"; flag = true; break;
                case 	"53 43 4D 49"               :  
                                    fileExtention =          "IMG"     ; fileInformation = "Img Software Bitmap"; flag = true; break;
                case 	"EB 3C 90 2A"               :  
                                    fileExtention =          "IMG"     ; fileInformation = "GEM Raster file"; flag = true; break;
                case 	"41 4F 4C 49 44 58"         :  
                                    fileExtention =          "IND"     ; fileInformation = "AOL client preferences|settings file"; flag = true; break;
                case 	"E3 10 00 01 00 00 00 00"  :	
                                    fileExtention =          "INFO"    ; fileInformation = "Amiga icon"; flag = true; break;
                case 	"54 68 69 73 20 69 73 20"  :	
                                    fileExtention =          "INFO"    ; fileInformation = "GNU Info Reader file"; flag = true; break;
                case 	"7A 62 65 78"               :  
                                    fileExtention =          "INFO"    ; fileInformation = "ZoomBrowser Image Index"; flag = true; break;
                case 	"43 44 30 30 31"            :  
                                    fileExtention =          "ISO"     ; fileInformation = "ISO-9660 CD Disc Image"; flag = true; break;
                case 	"2E 52 45 43"               :  
                                    fileExtention =          "IVR"     ; fileInformation = "RealPlayer video file (V11+)"; flag = true; break;
                case 	"5F 27 A8 89"               :  
                                    fileExtention =          "JAR"     ; fileInformation = "Jar archive"; flag = true; break;
                case 	"4A 41 52 43 53 00"         :  
                                    fileExtention =          "JAR"     ; fileInformation = "JARCS compressed archive"; flag = true; break;
                case 	"50 4B 03 04 14 00 08 00"  :	
                                    fileExtention =          "JAR"     ; fileInformation = "Java archive_2"; flag = true; break;
                case 	"FF D8 FF E0"               :  
                                    fileExtention =          ".JFIF, .JPE , .JPEG, .JPG"    ; fileInformation = " JPEG IMAGE || JFIF IMAGE FILE - jpeg  || JPEG IMAGE  || JPE IMAGE FILE - jpeg"; flag = true; break;
                case	"4A 47 03 0E"               :  
                                    fileExtention =          "JG"      ; fileInformation = "AOL ART file_1"; flag = true; break;
                case	"4A 47 04 0E"               :  
                                    fileExtention =          "JG"      ; fileInformation = "AOL ART file_2"; flag = true; break;
                case 	"4E 42 2A 00"               :  
                                    fileExtention =          ".JTPM, .JNT"     ; fileInformation = "MS Windows journal"; flag = true; break;
                case 	"00 00 00 0C 6A 50 20 20"  :	
                                    fileExtention =          "JP2"     ; fileInformation = "JPEG2000 image files"; flag = true; break;
                case 	"FF D8 FF E2"               :  
                                    fileExtention =          "JPEG"    ; fileInformation = "CANNON EOS JPEG FILE"; flag = true; break;
                case 	"FF D8 FF E3"               :  
                                    fileExtention =          "JPEG"    ; fileInformation = "SAMSUNG D500 JPEG FILE"; flag = true; break;
                case 	"FF D8 FF E1"               :  
                                    fileExtention =          "JPG"     ; fileInformation = "Digital camera JPG using Exchangeable Image File Format (EXIF)"; flag = true; break;
                case 	"FF D8 FF E8"               :  
                                    fileExtention =          "JPG"     ; fileInformation = "Still Picture Interchange File Format (SPIFF)"; flag = true; break;
                case 	"4B 47 42 5F 61 72 63 68"  :	
                                    fileExtention =          "KGB"     ; fileInformation = "KGB archive"; flag = true; break;
                case 	"49 44 33 03 00 00 00"      :  
                                    fileExtention =          "KOZ"     ; fileInformation = "Sprint Music Store audio"; flag = true; break;
                case 	"C8 00 79 00"               :  
                                    fileExtention =          "LBK"     ; fileInformation = "Jeppesen FliteLog file"; flag = true; break;
                case 	"7B 0D 0A 6F 20"            :  
                                    fileExtention =          ".LGD, .LGC"     ; fileInformation = "Windows application log"; flag = true; break;
                case 	"2D 6C 68"                  :  
                                    fileExtention =          ".LZH, .LHA"     ; fileInformation = "Compressed archive"; flag = true; break;
                case 	"21 3C 61 72 63 68 3E 0A"  :	
                                    fileExtention =          "LIB"     ; fileInformation = "Unix archiver (ar)|MS Program Library Common Object File Format (COFF)"; flag = true; break;
                case 	"49 54 4F 4C 49 54 4C 53"  :	
                                    fileExtention =          "LIT"     ; fileInformation = "MS Reader eBook"; flag = true; break;
                case 	"4C 00 00 00 01 14 02 00"  :	
                                    fileExtention =          "LNK"     ; fileInformation = "Windows shortcut file"; flag = true; break;
                case 	"2A 2A 2A 20 20 49 6E 73"  :	
                                    fileExtention =          "LOG"     ; fileInformation = "Symantec Wise Installer log"; flag = true; break;
                case 	"57 6F 72 64 50 72 6F"      :  
                                    fileExtention =          "LWP"     ; fileInformation = "Lotus WordPro file"; flag = true; break;
                case    "3C 3F 78 6D 6C 20 76 65"   :  
                                    fileExtention =          ".XML, .MSC, .MANIFEST"; fileInformation = "User Interface Language, MMC Snap-in Control file || Windows Visual Stylesheet"; flag = true; break;
                case 	"4D 41 72 30 00"            :  
                                    fileExtention =          "MAR"     ; fileInformation = "MAr compressed archive"; flag = true; break;
                case 	"4D 41 52 43"               :  
                                    fileExtention =          "MAR"     ; fileInformation = "Microsoft|MSN MARC archive"; flag = true; break;
                case 	"4D 41 52 31 00"            :  
                                    fileExtention =          "MAR"     ; fileInformation = "Mozilla archive"; flag = true; break;
                case 	"01 0F 00 00"               :  
                                    fileExtention =          "MDF"     ; fileInformation = "SQL Data Base"; flag = true; break;
                case 	"45 50"                     :  
                                    fileExtention =          "MDI"     ; fileInformation = "MS Document Imaging file"; flag = true; break;
                case 	"4D 54 68 64"               :  
                                    fileExtention =          "MID"     ; fileInformation = "MIDI sound file"; flag = true; break;
                case 	"56 65 72 73 69 6F 6E 20"  :	
                                    fileExtention =          "MIF"     ; fileInformation = "MapInfo Interchange Format file"; flag = true; break;
                case 	"1A 45 DF A3 93 42 82 88"  :	
                                    fileExtention =          "MKV"     ; fileInformation = "Matroska stream file"; flag = true; break;
                case 	"4D 49 4C 45 53"            :  
                                    fileExtention =          "MLS"     ; fileInformation = "Milestones project management file"; flag = true; break;
                case 	"4D 56 32 31 34"            :  
                                    fileExtention =          "MLS"     ; fileInformation = "Milestones project management file_1"; flag = true; break;
                case 	"4D 56 32 43"               :  
                                    fileExtention =          "MLS"     ; fileInformation = "Milestones project management file_2"; flag = true; break;
                case 	"4D 4C 53 57"               :  
                                    fileExtention =          "MLS"     ; fileInformation = "Skype localization data file"; flag = true; break;
                case 	"4D 4D 4D 44 00 00"         :  
                                    fileExtention =          "MMF"     ; fileInformation = "Yamaha Synthetic music Mobile Application Format"; flag = true; break;
                case 	"00 01 00 00 4D 53 49 53"   :  
                                    fileExtention =          "MNY"     ; fileInformation = "Microsoft Money file"; flag = true; break;
                case 	"FF FE 23 00 6C 00 69 00"  :	
                                    fileExtention =          "MOF"     ; fileInformation = "MSinfo file"; flag = true; break;
                case 	"6D 6F 6F 76"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_1"; flag = true; break;
                case 	"66 72 65 65"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_2"; flag = true; break;
                case 	"6D 64 61 74"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_3"; flag = true; break;
                case 	"77 69 64 65"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_4"; flag = true; break;
                case 	"70 6E 6F 74"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_5"; flag = true; break;
                case 	"73 6B 69 70"               :  
                                    fileExtention =          "MOV"     ; fileInformation = "QuickTime movie_6"; flag = true; break;
                case	"0C ED"                     :  
                                    fileExtention =          "MP"     ; fileInformation = "Monochrome Picture TIFF bitmap"; flag = true; break;
                case 	"49 44 33"                  :  
                                    fileExtention =          "MP3"     ; fileInformation = "MP3 audio file"; flag = true; break;
                case 	"00 00 01 BA"               :  
                                    fileExtention =          ".VOB, MPG"     ; fileInformation = "DVD video file"; flag = true; break;
                case 	"00 00 01 B3"               :  
                                    fileExtention =          "MPG"     ; fileInformation = "MPEG video file"; flag = true; break;
                case 	"23 20"                     :  
                                    fileExtention =          "MSI"     ; fileInformation = "Cerius2 file"; flag = true; break;
                case 	"0E 4E 65 72 6F 49 53 4F"  :	
                                    fileExtention =          "NRI"     ; fileInformation = "Nero CD compilation"; flag = true; break;
                case 	"1A 00 00 04 00 00"         :  
                                    fileExtention =          "NSF"     ; fileInformation = "Lotus Notes database"; flag = true; break;
                case 	"4E 45 53 4D 1A 01"         :  
                                    fileExtention =          "NSF"     ; fileInformation = "NES Sound file"; flag = true; break;
                case 	"1A 00 00"                  :  
                                    fileExtention =          "NTF"     ; fileInformation = "Lotus Notes database template"; flag = true; break;
                case 	"4E 49 54 46 30"            :  
                                    fileExtention =          "NTF"     ; fileInformation = "National Imagery Transmission Format file"; flag = true; break;
                case 	"30 31 4F 52 44 4E 41 4E"  :	
                                    fileExtention =          "NTF"     ; fileInformation = "National Transfer Format Map"; flag = true; break;
                case 	"4D 52 56 4E"               :  
                                    fileExtention =          "NVRAM"   ; fileInformation = "VMware BIOS state file"; flag = true; break;
                case 	"4C 01"                     :  
                                    fileExtention =          "OBJ"     ; fileInformation = "MS COFF relocatable object code"; flag = true; break;
                case 	"80"                        :  
                                    fileExtention =          "OBJ"     ; fileInformation = "Relocatable object code"; flag = true; break;
                case 	"4F 67 67 53 00 02 00 00"  :	
                                    fileExtention =          ".OGG, .OGV, .OGX, OGA"     ; fileInformation = "Ogg Vorbis Codec compressed file"; flag = true; break;
                case 	"E4 52 5C 7B 8C D8 A7 4D"  :	
                                    fileExtention =          "ONE"     ; fileInformation = "MS OneNote note"; flag = true; break;
                case 	"FD FF FF FF 20"            :  
                                    fileExtention =          "OPT"     ; fileInformation = "Developer Studio subheader"; flag = true; break;
                case 	"41 4F 4C 56 4D 31 30 30"  :	
                                    fileExtention =          ".PFC, ORG"     ; fileInformation = "AOL personal file cabinet"; flag = true; break;
                case 	"64 00 00 00"               :  
                                    fileExtention =          "P10"     ; fileInformation = "Intel PROset|Wireless Profile"; flag = true; break;
                case 	"1A 0B"                     :  
                                    fileExtention =          "PAK"     ; fileInformation = "PAK Compressed archive file"; flag = true; break;
                case 	"50 41 43 4B"               :  
                                    fileExtention =          "PAK"     ; fileInformation = "Quake archive file"; flag = true; break;
                case 	"47 50 41 54"               :  
                                    fileExtention =          "PAT"     ; fileInformation = "GIMP pattern file"; flag = true; break;
                case 	"50 41 58"                  :  
                                    fileExtention =          "PAX"     ; fileInformation = "PAX password protected bitmap"; flag = true; break;
                case 	"56 43 50 43 48 30"         :  
                                    fileExtention =          "PCH"     ; fileInformation = "Visual C PreCompiled header"; flag = true; break;
                case 	"0A 05 01 01"               :  
                                    fileExtention =          "PCX"     ; fileInformation = "ZSOFT Paintbrush file_3"; flag = true; break;
                case 	"0A 03 01 01"               :  
                                    fileExtention =          "PCX"     ; fileInformation = "ZSOFT Paintbrush file_2"; flag = true; break;
                case 	"0A 02 01 01"               :  
                                    fileExtention =          "PCX"     ; fileInformation = "ZSOFT Paintbrush file_1"; flag = true; break;
                case 	"4D 69 63 72 6F 73 6F 66"   :  
                                    fileExtention =          ".WPL, .SNL, PDB"     ; fileInformation = "Windows Media Player playlist || Visual Studio .NET file || MS C++ debugging symbols file"; flag = true; break;
                case 	"4D 2D 57 20 50 6F 63 6B"  :	
                                    fileExtention =          "PDB"     ; fileInformation = "Merriam-Webster Pocket Dictionary"; flag = true; break;
                case 	"AC ED 00 05 73 72 00 12"  :	
                                    fileExtention =          "PDB"     ; fileInformation = "BGBlitz position database file"; flag = true; break;
                case 	"73 7A 65 7A"               :  
                                    fileExtention =          "PDB"     ; fileInformation = "PowerBASIC Debugger Symbols"; flag = true; break;
                case 	"73 6D 5F"                  :  
                                    fileExtention =          "PDB"     ; fileInformation = "PalmOS SuperMemo"; flag = true; break;
                case	"11 00 00 00 53 43 43 41"  :	
                                    fileExtention =          "PF"     ; fileInformation = "Windows prefetch file"; flag = true; break;
                case 	"50 47 50 64 4D 41 49 4E"  :	
                                    fileExtention =          "PGD"     ; fileInformation = "PGP disk image"; flag = true; break;
                case 	"50 35 0A"                  :  
                                    fileExtention =          "PGM"     ; fileInformation = "Portable Graymap Graphic"; flag = true; break;
                case 	"99 01"                     :  
                                    fileExtention =          "PKR"     ; fileInformation = "PGP public keyring"; flag = true; break;
                case 	"89 50 4E 47 0D 0A 1A 0A"  :	
                                    fileExtention =          "PNG"     ; fileInformation = "PNG image"; flag = true; break;
                case 	"FD FF FF FF 43 00 00 00"  :	
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_6"; flag = true; break;
                case 	"FD FF FF FF 1C 00 00 00"  :	
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_5"; flag = true; break;
                case 	"FD FF FF FF 0E 00 00 00"  :	
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_4"; flag = true; break;
                case 	"A0 46 1D F0"               :  
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_3"; flag = true; break;
                case 	"0F 00 E8 03"               :  
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_2"; flag = true; break;
                case 	"00 6E 1E F0"               :  
                                    fileExtention =          "PPT"     ; fileInformation = "PowerPoint presentation subheader_1"; flag = true; break;
                case 	"74 42 4D 50 4B 6E 57 72"  :	
                                    fileExtention =          "PRC"     ; fileInformation = "Palmpilot resource file"; flag = true; break;
                case 	"42 4F 4F 4B 4D 4F 42 49"  :	
                                    fileExtention =          "PRC"     ; fileInformation = "Palmpilot resource file"; flag = true; break;
                case 	"38 42 50 53"               :  
                                    fileExtention =          "PSD"     ; fileInformation = "Photoshop image"; flag = true; break;
                case 	"7E 42 4B 00"               :  
                                    fileExtention =          "PSP"     ; fileInformation = "Corel Paint Shop Pro image"; flag = true; break;
                case 	"7B 5C 70 77 69"            :  
                                    fileExtention =          "PWI"     ; fileInformation = "MS WinMobile personal note"; flag = true; break;
                case 	"E3 82 85 96"               :  
                                    fileExtention =          "PWL"     ; fileInformation = "Win98 password file"; flag = true; break;
                case 	"B0 4D 46 43"               :  
                                    fileExtention =          "PWL"     ; fileInformation = "Win95 password file"; flag = true; break;
                case 	"45 86 00 00 06 00"         :  
                                    fileExtention =          "QBB"     ; fileInformation = "QuickBooks backup"; flag = true; break;
                case 	"AC 9E BD 8F 00 00"         :  
                                    fileExtention =          "QDF"     ; fileInformation = "QDF Quicken data"; flag = true; break;
                case 	"51 45 4C 20"               :  
                                    fileExtention =          "QEL"     ; fileInformation = "QDL Quicken data"; flag = true; break;
                case 	"51 46 49"                  :  
                                    fileExtention =          "QEMU"    ; fileInformation = "cow Disk Image"; flag = true; break;
                case 	"03 00 00 00"               :  
                                    fileExtention =          "QPH"     ; fileInformation = "Quicken price history"; flag = true; break;
                case 	"00 00 4D 4D 58 50 52"      :  
                                    fileExtention =          "QXD"     ; fileInformation = "Quark Express (Motorola)"; flag = true; break;
                case 	"00 00 49 49 58 50 52"      :  
                                    fileExtention =          "QXD"     ; fileInformation = "Quark Express (Intel)"; flag = true; break;
                case	"2E 72 61 FD 00"            :  
                                    fileExtention =          "RA"      ; fileInformation = "RealAudio streaming media"; flag = true; break;
                case	"2E 52 4D 46 00 00 00 12"  :	
                                    fileExtention =          "RA"      ; fileInformation = "RealAudio file"; flag = true; break;
                case 	"72 74 73 70 3A 2F 2F"      :  
                                    fileExtention =          "RAM"     ; fileInformation = "RealMedia metafile"; flag = true; break;
                case 	"52 61 72 21 1A 07 00"      :  
                                    fileExtention =          "RAR"     ; fileInformation = "WinRAR compressed archive"; flag = true; break;
                case 	"52 45 47 45 44 49 54"      :  
                                    fileExtention =          ".SUD, REG"     ; fileInformation = "WinNT Registry|Registry Undo files, WinNT Registry|Registry Undo files"; flag = true; break;
                case 	"FF FE"                     :  
                                    fileExtention =          "REG"     ; fileInformation = "Windows Registry file"; flag = true; break;
                case 	"01 DA 01 01 00 03"         :  
                                    fileExtention =          "RGB"     ; fileInformation = "Silicon Graphics RGB Bitmap"; flag = true; break;
                case	"2E 52 4D 46"               :  
                                    fileExtention =          ".RMVB, .RM"      ; fileInformation = "RealMedia streaming media"; flag = true; break;
                case 	"ED AB EE DB"               :  
                                    fileExtention =          "RPM"     ; fileInformation = "RedHat Package Manager"; flag = true; break;
                case 	"43 23 2B 44 A4 43 4D A5"  :	
                                    fileExtention =          "RTD"     ; fileInformation = "RagTime document"; flag = true; break;
                case 	"7B 5C 72 74 66 31"         :  
                                    fileExtention =          "RTF"     ; fileInformation = "RTF file"; flag = true; break;
                case 	"5B 76 65 72 5D"            :  
                                    fileExtention =          "SAM"     ; fileInformation = "Lotus AMI Pro document_2"; flag = true; break;
                case 	"5B 56 45 52 5D"            :  
                                    fileExtention =          "SAM"     ; fileInformation = "Lotus AMI Pro document_1"; flag = true; break;
                case 	"24 46 4C 32 40 28 23 29"  :	
                                    fileExtention =          "SAV"     ; fileInformation = "SPSS Data file"; flag = true; break;
                case 	"4D 5A "                    :  
                                    fileExtention =          "SCR"     ; fileInformation = "Screen saver"; flag = true; break;
                case 	"53 4D 41 52 54 44 52 57"  :	
                                    fileExtention =          "SDR"     ; fileInformation = "SmartDraw Drawing file"; flag = true; break;
                case 	"48 48 47 42 31"            :  
                                    fileExtention =          "SH3"     ; fileInformation = "Harvard Graphics presentation file"; flag = true; break;
                case 	"67 49 00 00"               :  
                                    fileExtention =          "SHD"     ; fileInformation = "Win2000|XP printer spool file"; flag = true; break;
                case 	"4B 49 00 00"               :  
                                    fileExtention =          "SHD"     ; fileInformation = "Win9x printer spool file"; flag = true; break;
                case 	"66 49 00 00"               :  
                                    fileExtention =          "SHD"     ; fileInformation = "WinNT printer spool file"; flag = true; break;
                case 	"68 49 00 00"               :  
                                    fileExtention =          "SHD"     ; fileInformation = "Win Server 2003 printer spool file"; flag = true; break;
                case 	"53 48 4F 57"               :  
                                    fileExtention =          "SHW"     ; fileInformation = "Harvard Graphics presentation"; flag = true; break;
                case 	"53 74 75 66 66 49 74 20"  :	
                                    fileExtention =          "SIT"     ; fileInformation = "StuffIt compressed archive"; flag = true; break;
                case 	"53 49 54 21 00"            :  
                                    fileExtention =          "SIT"     ; fileInformation = "StuffIt archive"; flag = true; break;
                case 	"07 53 4B 46"               :  
                                    fileExtention =          "SKF"     ; fileInformation = "SkinCrafter skin"; flag = true; break;
                case 	"95 01"                     :  
                                    fileExtention =          "SKR"     ; fileInformation = "PGP secret keyring_2"; flag = true; break;
                case 	"95 00"                     :  
                                    fileExtention =          "SKR"     ; fileInformation = "PGP secret keyring_1"; flag = true; break;
                case 	"3A 56 45 52 53 49 4F 4E"  :	
                                    fileExtention =          "SLE"     ; fileInformation = "Surfplan kite project file"; flag = true; break;
                case 	"41 43 76"                  :  
                                    fileExtention =          "SLE"     ; fileInformation = "Steganos virtual secure drive"; flag = true; break;
                case 	"00 1E 84 90 00 00 00 00"  :	
                                    fileExtention =          "SNM"     ; fileInformation = "Netscape Communicator (v4) mail folder"; flag = true; break;
                case 	"FD FF FF FF 04"            :  
                                    fileExtention =          "SUO"     ; fileInformation = "Visual Studio Solution subheader"; flag = true; break;
                case 	"46 57 53"                  :  
                                    fileExtention =          "SWF"     ; fileInformation = "Shockwave Flash player"; flag = true; break;
                case 	"43 57 53"                  :  
                                    fileExtention =          "SWF"     ; fileInformation = "Shockwave Flash file"; flag = true; break;
                case 	"FF"                        :  
                                    fileExtention =          "SYS"     ; fileInformation = "Windows executable"; flag = true; break;
                case 	"FF 4B 45 59 42 20 20 20"  :	
                                    fileExtention =          "SYS"     ; fileInformation = "Keyboard driver file"; flag = true; break;
                case 	"FF FF FF FF"               :  
                                    fileExtention =          "SYS"     ; fileInformation = "DOS system driver"; flag = true; break;
                case 	"41 4D 59 4F"               :  
                                    fileExtention =          "SYW"     ; fileInformation = "Harvard Graphics symbol graphic"; flag = true; break;
                case 	"75 73 74 61 72"            :  
                                    fileExtention =          "TAR"     ; fileInformation = "Tape Archive"; flag = true; break;
                case 	"1F A0"                     :  
                                    fileExtention =          "TAR.Z"   ; fileInformation = "Compressed tape archive_2"; flag = true; break;
                case 	"1F 9D 90"                  :  
                                    fileExtention =          "TAR.Z"   ; fileInformation = "Compressed tape archive_1"; flag = true; break;
                case 	"B4 6E 68 44"               :  
                                    fileExtention =          "TIB"     ; fileInformation = "Acronis True Image"; flag = true; break;
                case 	"4D 4D 00 2A"               :  
                                    fileExtention =          ".TIFF, .TIF"     ; fileInformation = "TIFF file_3"; flag = true; break;
                case 	"49 49 2A 00"               :  
                                    fileExtention =          ".TIFF, .TIF"     ; fileInformation = "TIFF file_2"; flag = true; break;
                case 	"49 20 49"                  :  
                                    fileExtention =          ".TIFF, .TIF"     ; fileInformation = "TIFF file_1"; flag = true; break;
                case 	"4D 4D 00 2B"               :  
                                    fileExtention =          ".TIFF, .TIF"     ; fileInformation = "TIFF file_4"; flag = true; break;
                case 	"4D 53 46 54 02 00 01 00"  :	
                                    fileExtention =          "TLB"     ; fileInformation = "OLE|SPSS|Visual C++ library file"; flag = true; break;
                case 	"01 10"                     :  
                                    fileExtention =          "TR1"     ; fileInformation = "Novell LANalyzer capture file"; flag = true; break;
                case 	"55 43 45 58"               :  
                                    fileExtention =          "UCE"     ; fileInformation = "Unicode extensions"; flag = true; break;
                case 	"55 46 41 C6 D2 C1"         :  
                                    fileExtention =          "UFA"     ; fileInformation = "UFA compressed archive"; flag = true; break;
                case 	"45 4E 54 52 59 56 43 44"  :	
                                    fileExtention =          "VCD"     ; fileInformation = "VideoVCD|VCDImager file"; flag = true; break;
                case 	"42 45 47 49 4E 3A 56 43"  :	
                                    fileExtention =          "VCF"     ; fileInformation = "vCard"; flag = true; break;
                case 	"5B 4D 53 56 43"            :  
                                    fileExtention =          "VCW"     ; fileInformation = "Visual C++ Workbench Info File"; flag = true; break;
                case 	"63 6F 6E 65 63 74 69 78"   :  
                                    fileExtention =          "VHD"     ; fileInformation = "Virtual PC HD image"; flag = true; break;
                case 	"4B 44 4D"                  :  
                                    fileExtention =          "VMDK"    ; fileInformation = "VMware 4 Virtual Disk"; flag = true; break;
                case 	"23 20 44 69 73 6B 20 44"   :  
                                    fileExtention =          "VMDK"    ; fileInformation = "VMware 4 Virtual Disk description"; flag = true; break;
                case 	"43 4F 57 44"               :  
                                    fileExtention =          "VMDK"    ; fileInformation = "VMware 3 Virtual Disk"; flag = true; break;
                case 	"81 32 84 C1 85 05 D0 11"  :	
                                    fileExtention =          "WAB"     ; fileInformation = "Outlook Express address book (Win95)"; flag = true; break;
                case 	"9C CB CB 8D 13 75 D2 11"  :	
                                    fileExtention =          "WAB"     ; fileInformation = "Outlook address file"; flag = true; break;
                case 	"3E 00 03 00 FE FF 09 00"  :	
                                    fileExtention =          "WB3"     ; fileInformation = "Quatro Pro for Windows 7.0"; flag = true; break;
                case 	"00 00 02 00 06 04 06 00"  :	
                                    fileExtention =          "WK1"     ; fileInformation = "Lotus 1-2-3 (v1)"; flag = true; break;
                case 	"00 00 1A 00 00 10 04 00"  :	
                                    fileExtention =          "WK3"     ; fileInformation = "Lotus 1-2-3 (v3)"; flag = true; break;
                case 	"00 00 1A 00 02 10 04 00"  :	
                                    fileExtention =          ".WK5, .WK4"     ; fileInformation = "Lotus 1-2-3 (v4|v5)"; flag = true; break;
                case 	"0E 57 4B 53"               :  
                                    fileExtention =          "WKS"     ; fileInformation = "DeskMate Worksheet"; flag = true; break;
                case 	"FF 00 02 00 04 04 05 54"  :	
                                    fileExtention =          "WKS"     ; fileInformation = "Works for Windows spreadsheet"; flag = true; break;
                case 	"D7 CD C6 9A"               :  
                                    fileExtention =          "WMF"     ; fileInformation = "Windows graphics metafile"; flag = true; break;
                case	"FF 57 50 43"               :  
                                    fileExtention =          ".WP5, .WP6, .WPD, .WPG, .WPP, .WP"      ; fileInformation = "WordPerfect text and graphics"; flag = true; break;
                case 	"81 CD AB"                  :  
                                    fileExtention =          "WPF"     ; fileInformation = "WordPerfect text"; flag = true; break;
                case 	"BE 00 00 00 AB"            :  
                                    fileExtention =          "WRI"     ; fileInformation = "MS Write file_3"; flag = true; break;
                case 	"32 BE"                     :  
                                    fileExtention =          "WRI"     ; fileInformation = "MS Write file_2"; flag = true; break;
                case 	"31 BE"                     :  
                                    fileExtention =          "WRI"     ; fileInformation = "MS Write file_1"; flag = true; break;
                case	"1D 7D"                     :  
                                    fileExtention =          "WS"      ; fileInformation = "WordStar Version 5.0|6.0 document"; flag = true; break;
                case 	"57 53 32 30 30 30"         :  
                                    fileExtention =          "WS2"     ; fileInformation = "WordStar for Windows file"; flag = true; break;
                case 	"FD FF FF FF 10"   :           
                                        fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_2"; flag = true; break;
                case 	"09 08 10 00 00 06 05 00"  :	
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_1"; flag = true; break;
                case 	"FD FF FF FF 29"            :  
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_7"; flag = true; break;
                case 	"FD FF FF FF 28"            :  
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_6"; flag = true; break;
                case 	"FD FF FF FF 23"            :  
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_5"; flag = true; break;
                case 	"FD FF FF FF 22"            :  
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_4"; flag = true; break;
                case 	"FD FF FF FF 1F"            :  
                                    fileExtention =          "XLS"     ; fileInformation = "Excel spreadsheet subheader_3"; flag = true; break;
                case 	"58 50 43 4F 4D 0A 54 79"   :  
                                    fileExtention =          "XPT"     ; fileInformation = "XPCOM libraries"; flag = true; break;
                case 	"50 4B 03 04 14 00 01 00"  :	
                                    fileExtention =          "ZIP"     ; fileInformation = "ZLock Pro encrypted ZIP"; flag = true; break;
                case 	"50 4B 07 08"               :  
                                    fileExtention =          "ZIP"     ; fileInformation = "PKZIP archive_3"; flag = true; break;
                case 	"50 4B 05 06"               :  
                                    fileExtention =          "ZIP"     ; fileInformation = "PKZIP archive_2"; flag = true; break;
                case 	"50 4B 53 70 58" 	        :  
                                    fileExtention =          "ZIP"     ; fileInformation = "PKSFX self-extracting archive"; flag = true; break;
                case 	"50 4B 4C 49 54 45"         :  
                                    fileExtention =          "ZIP"     ; fileInformation = "PKLITE archive"; flag = true; break;
                case 	"57 69 6E 5A 69 70"         :  
                                    fileExtention =          "ZIP"     ; fileInformation = "WinZip compressed archive"; flag = true; break;
                case 	"5A 4F 4F 20"               :  
                                    fileExtention =          "ZOO"     ; fileInformation = "ZOO compressed archive"; flag = true; break;
                case 	"7F 45 4C 46 02 01 01 00"               :  
                                    fileExtention =          ".OUT, .APPIMAGE"     ; fileInformation = "gcc binary for linux"; flag = true; break;
                case 	"41 4E 44 52 4F 49 44 21"               :  
                                    fileExtention =          ".IMG"     ; fileInformation = "flashable Image"; flag = true; break;
                // case 	"00 00 00 18 66 74 79 70"               :  
                //                     fileExtention =          "MP4"     ; fileInformation = "MP4 Video"; flag = true; break;
                default :  fileExtention = "unknown"; fileInformation = "not recorgnised file"; 
            }
        }              
    }

    public static void main(String[] args) {
        HexDataBase obj = new HexDataBase();
        obj.getfileInformation("4D 5A 90 00 03 00 00 00");
        System.out.print(obj.fileExtention);
    }
}