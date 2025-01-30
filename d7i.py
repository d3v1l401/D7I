import idc
import idautils
import idaapi
import os

print("d3vsite.org / by d3vil401 - Python rewrite of Encryqed's Dumper7 native plugin ")

DUMPER_MAPPINGS = "C:\\Dumper-7\\<your game name>\\IDAMappings\\<your game mappings name>.idmap"

baseAddress = ida_nalt.get_imagebase()
DumpSize = os.path.getsize(DUMPER_MAPPINGS)

print("Base Address:", hex(baseAddress))
print("Dump location:", DUMPER_MAPPINGS)
print("Dump size:", DumpSize)

print("")

Entries = list()

class DumpEntry:
    def __init__(self, offset, nameLen, name):
        self.Offset = offset
        self.NameLength = nameLen
        self.Name = str(name, encoding='utf-8')
        
    def Dump(self):
        print(hex(baseAddress + self.Offset), " -> ", self.Name)
        
    def GetEntrySize(self):
        return 4 + 2 + self.NameLength
        
    def GetRVA(self):
        return self.Offset
        
    def GetName(self):
        return self.Name
        
def AddBookmarkIfNone(offset, comment):
    for bSlot in range (0, 1024, 1):
        bookmark = idc.get_bookmark(bSlot)
        if (bookmark == offset):
            return
        else:
            idc.put_bookmark(offset, 0, 0, 0, bSlot, comment)

with open(DUMPER_MAPPINGS, mode="rb") as file:
    content = file.read()
    remainingData = DumpSize
    index = 0
    
    while remainingData > 0:
        _offset = struct.unpack("I", content[index : index + 4])[0]
        _nameLen = struct.unpack("H", content[index + 4 : index + 6])[0]
        _name = struct.unpack("%ds" % _nameLen, content[index + 6 : index + 6 + _nameLen])[0]
            
        newEntry = DumpEntry(_offset, _nameLen, _name)
        Entries.append(newEntry)
            
        index += newEntry.GetEntrySize()
        remainingData -= newEntry.GetEntrySize()
    
print("Done processing", len(Entries), "entries")
print("Starting to rename...")

for funcEntry in Entries:
    funcEntry.Dump()
    VA = baseAddress + funcEntry.GetRVA()
    idaapi.set_name(VA, funcEntry.GetName(), idaapi.SN_NOCHECK)
    # AddBookmarkIfNone(VA, funcEntry.GetName()) # Slow + you only have 1024 slots :\
    idc.set_cmt(VA, funcEntry.GetName(), 1) # good with https://github.com/merces/showcomments/blob/main/showcomments.py
    
        
print("Renaming done")
    