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

from GCodeYaraLib import GCodeYaraPrinterProfile,  GCodeYaraScanner



def main():
    
    # Generate and save a json file containing printer settings
    GCodeYaraPrinterProfile("PrinterProfile.json")
    
    # scan the gcode file using the specified rules and printer profile
    gcys = GCodeYaraScanner("TestFile.gcode",  "Rules.yar",  "PrinterProfile.json")
    matches = gcys.ScanFile()
    for match in matches:
        print(str(match))
    
    input("Hit Enter")
    
if __name__ == "__main__":
    main()
