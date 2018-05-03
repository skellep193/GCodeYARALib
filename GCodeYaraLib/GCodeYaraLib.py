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

import json
import yara
import os

class GCodeYaraPrinterProfile:
    
    basicSettings = ["PRINTER_NAME","MAX_X", "MAX_Y", "MAX_Z","MAX_ACC","MAX_EXT_TEMP_C", "MAX_BED_TEMP_C"]
    
    def __init__(self, outYarFileName,  printerSettings = None):
        self.filename = outYarFileName
        
        if printerSettings == None:
            self.printerSettings = self.BuildProfile()
        else:
            self.printerSettings = printerSettings
        
        # save as json
        with open(self.filename, "w+") as js:
                json.dump(self.printerSettings, js )
        
    def BuildProfile(self):
        retVal = {}
        print("Provide values for the following printer settings")
        for setting in self.basicSettings:
            temp = input(setting +":")
            retVal[setting] = temp
        return retVal

class GCodeYaraScanner:
    
    def __init__(self,  gcodeScanFile,yarRuleFile, jsonPrinterConfigFile):
        self.gcodeFile = gcodeScanFile
        self.yarPrinterFile = jsonPrinterConfigFile
        self.yarRuleFile = yarRuleFile
        
        with open(jsonPrinterConfigFile, 'r' ) as js:
            self.printerSettings = json.load(js)
        
    def ScanFile(self):

        rules = yara.compile(filepaths={
            'r1': self.yarRuleFile
        }, externals=self.printerSettings)
        
        matches = rules.match(self.gcodeFile)
        #return(matches)
        return self.PerformSecondaryScan(matches)
    
    # for POC purposes only. Demonstrates overheating beyond assigned MAX_EXT_TEMP_C
    def PerformSecondaryScan(self,  matches):
        filteredMatches = []
        for match in matches:
            for string in match.strings:
                 num = int(str(string[2])[8:-1])
                 #print(num)
                 #print(self.printerSettings["MAX_EXT_TEMP_C"])
                 if num > int(self.printerSettings["MAX_EXT_TEMP_C"]):
                     filteredMatches.append(string)
        return filteredMatches
    
def ValidateFileInput(checkname,  extension):
    if os.path.exists(checkname) != 1:
                    raise LookupError("File not found")
    if checkname.endswith("." + extension) != 1:
                    raise LookupError("ncorrect file extension")
    if os.stat(checkname).st_size == 0:
                    raise LookupError("File is empty")
    return(True)
