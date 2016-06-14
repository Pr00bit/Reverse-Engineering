#------PEreader by Pr0bit-----------------
#------ver 1.0 2016 ----------------------
from binascii import hexlify
from tkinter.filedialog import askopenfile
import struct

print ("       --Portable executable analyser by Pr0bit--")
print()

myfile = askopenfile(title='Choose file to open', mode='rb')

#--------- Check if this is valid PE file----------- OK!!
loadedfile = myfile.read(100)
myfile.seek (0)
k =myfile.read(2)


if k ==b'MZ':
    print ('     --the file is valid PE file, it contains: MZ-- ')
else:
    print ('      File not recognised',k)


#--------- PE header location----------- OK!!
g = myfile.read(100)
myfile.seek (60)
k60 =myfile.read(1)
k61 =myfile.read(1)
k62 =myfile.read(1)
k63 =myfile.read(1)
 
raw = b''.join([k63,k62,k61,k60])  # laczenie bajtow
u=int.from_bytes(raw, byteorder='big') # przelicza ciag byte na integer
u1 =hex(u)
#w=(hexlify(raw).decode('ascii'))   # konersja bajtow do ascii
print()
print ('    PE header starts at:',  u,'decimal','/',u1,'hex')

#--------Main / address of entry point -----OK!!
print ('------------BASIC MODULE---------')
myfile.seek(u +40)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    Adres of entry point: ' ,  w)
#--------Imagebase -----OK!!
myfile.seek(u +52)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    Imgebase: ' ,  w)
#-------- SizeOfImage -----OK!!
myfile.seek(u +52+28)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    SizeOfImage: ' ,  w)
#-------- SizeOfCode -----OK!!
myfile.seek(u +28)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    SizeOfCode: ' ,  w)
#--------Baseofdata -----OK!!
myfile.seek(u+48)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('    Baseofdata: ' ,  w)
#-------- SectionAlignment -----OK!!
myfile.seek(u+56)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   SectionAlignment: ' ,  w)
#--------FileAlignment -----OK!!
myfile.seek(u+60)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   FileAlignment: ' ,  w)
 
#-------- Magic -----OK!!
myfile.seek(u +24)
k30 =myfile.read(1)
k31 =myfile.read(1)

raw=b''.join([k31,k30])
w=(hexlify(raw).decode('ascii'))
#hex (raw)
print ('    Magic: ' ,  w)
#-------- Subsystem -----OK!!
myfile.seek(u +52+28+12)
k30 =myfile.read(1)
k31 =myfile.read(1)
 
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    Subsystem: ' ,  w)
 
#--------PE header / TimeDateStamp----------completed
myfile.seek(u +8)
k136 =myfile.read(1)
k137 =myfile.read(1)
k138 =myfile.read(1)
k139 =myfile.read(1)
raw=b''.join([k139,k138,k137,k136])

w=(hexlify(raw).decode('ascii'))
print ('TimeDateStamp:      ',w)
#-------- SizeOfHeaders -----OK!!
myfile.seek(u +56+28)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   SizeOfHeaders: ' ,  w)
#--------Charalteristics---------completed
myfile.seek(u +22)
k136 =myfile.read(1)
k137 =myfile.read(1)

raw=b''.join([k137,k136])

w=(hexlify(raw).decode('ascii'))
print ('Characteristics:      ',w)
#-------- Checksum-----OK!!
myfile.seek(u +60+28)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   checksum: ' ,  w)
#--------SizeOfOptionalHeader---------completed
myfile.seek(u +20)
k136 =myfile.read(1)
k137 =myfile.read(1)

raw=b''.join([k137,k136])

w=(hexlify(raw).decode('ascii'))
print ('SizeOfOptionalHeader:      ',w)
#-------- C NumberOfRvaAndSizes-----OK!!
myfile.seek(u +60+28+28)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)
 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('    NumberOfRvaAndSizes: ' ,  w)
#--------------Section Data Directory ----------------
print ()
print('-------------Section Data Directory ----------------')
#-------- export directory-----
  # ------RVA-------
   
myfile.seek(u +120)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   RVA of export directory: ' ,  w)
# ------size-------
myfile.seek(u +124)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   Size of export directory: ' ,  w)
#-------- import directory-----
  # ------RVA-------
   
myfile.seek(u +128)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   RVA of import directory: ' ,  w)
# ------size-------
myfile.seek(u + 132)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   Size of import directory: ' ,  w)
#-------- Resources directory-----
  # ------RVA-------
   
myfile.seek(u +136)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   RVA of Resources directory: ' ,  w)
# ------size-------
myfile.seek(u +140)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   Size of Resources directory: ' ,  w)
#-------- Debug directory-----
  # ------RVA-------
   
myfile.seek(u +168)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   RVA of Debug directory: ' ,  w)
# ------size-------
myfile.seek(u +172)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   Size of Debug directory: ' ,  w)
#-------- TLS directory-----
  # ------RVA-------
   
myfile.seek(u +192)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   RVA of TLS directory: ' ,  w)
# ------size-------
myfile.seek(u +196)
k30 =myfile.read(1)
k31 =myfile.read(1)
k32 =myfile.read(1)
k33 =myfile.read(1)

 
raw=b''.join([k33,k32,k31,k30])
w=(hexlify(raw).decode('ascii'))
print ('   Size of TLS directory: ' ,  w)
#-----------------------------------------
#- -------------------sekcja sections:
print('---------------SECTION MODULE--------------')
# - sekcja        TEXT-----------------------
secstart = myfile.seek(u+249)
myfile.seek(0+u+249)#  BYTE  Name 
print('section name:',myfile.read(4))
  
  #  DWORD VirtualSize;         ok
myfile.seek(7+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   VirtualSize: ' ,  w)

  #  DWORD Virtualoffset;    - ok
myfile.seek(11+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Virtualoffset: ' ,  w)
  #  DWORD Realoffset; ----------------ok
myfile.seek(19+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realoffset: ' ,  w)
  #  DWORD Realsize;-------------------ok
myfile.seek(15+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realsize: ' ,  w)
  #  DWORD Flags;------------------ok
myfile.seek(35+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Flags: ' ,  w)
#----------- sekcja DATA -------------
#------------------------------------

myfile.seek(40+u+249)#  BYTE  Name 
print('section name:',myfile.read(4))
u=u+40
  #  DWORD VirtualSize;         ok
myfile.seek(7+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   VirtualSize: ' ,  w)

  #  DWORD Virtualoffset;    - ok
myfile.seek(11+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Virtualoffset: ' ,  w)
  #  DWORD Realoffset; ----------------ok
myfile.seek(19+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realoffset: ' ,  w)
  #  DWORD Realsize;-------------------ok
myfile.seek(15+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realsize: ' ,  w)
  #  DWORD Flags;------------------ok
myfile.seek(35+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Flags: ' ,  w)

# ---------sekcja RSRC------------
myfile.seek(40+u+249)#  BYTE  Name 
print('section name:',myfile.read(4))
u=u+40
  #  DWORD VirtualSize;         ok
myfile.seek(7+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   VirtualSize: ' ,  w)

  #  DWORD Virtualoffset;    - ok
myfile.seek(11+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Virtualoffset: ' ,  w)
  #  DWORD Realoffset; ----------------ok
myfile.seek(19+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realoffset: ' ,  w)
  #  DWORD Realsize;-------------------ok
myfile.seek(15+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Realsize: ' ,  w)
  #  DWORD Flags;------------------ok
myfile.seek(35+u+249)
bit1=myfile.read(1)
bit2=myfile.read(1)
bit3=myfile.read(1)
bit4=myfile.read(1)
raw=b''.join([bit4,bit3,bit2,bit1])
w=(hexlify(raw).decode('ascii'))
print ('   Flags: ' ,  w)
 	
 
