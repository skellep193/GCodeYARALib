#   GCodeYaraLib uses YARA to allow for GCode parsing and identification of potentially disruptive or dangerous 
#    g-code instructions or instruction sequences.
#    Copyright (C) 2018 Patrick Skelley, <pskelley@albany.edu>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import yara
import os.stat, os.path

class GCodeYaraPrinterProfile:
    def __init__(self,  filename):
        ValidateFileInput(filename)
        self.filename = filename
        
    def GenerateProfile(self):
        return True
        
class GCodeYaraScanner:
    
    def __init__(self,  gcodeScanFile,yarRuleFile, yarPrinterConfigFile):
        ValidateFileInput(gcodeScanFile,  ".gcode")
        ValidateFileInput(yarPrinterConfigFile, ".yar")
        self.gcodeFile = gcodeScanFile
        self.yarPrinterFile = yarPrinterConfigFile
        self.yarRulefile = yarRuleFile
        
    def ScanFile(self):
        try:
            rules = yara.compile(filepaths={
                'r1': self.yarPrinterFile, 
                'r2': self.yarRuleFile
            })
            
            matches = rules.match(self.gcodeFile)
            
        except:
            return None
            
        return matches
        
    
def ValidateFileInput(checkname,  extension):
    if os.path.exists(checkname) != 1:
                    raise LookupError("File not found")
    if checkname.endswith("." + extension) != 1:
                    raise LookupError("ncorrect file extension")
    if os.stat(checkname).st_size == 0:
                    raise LookupError("File is empty")
    return(True)
