#   GCodeHashLib embeds MD5 and SHA256 checksums within gcode files for pre-print validation purposes
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

from GCodeHashLib import GCodeSHA256Checksum,  GCodeMD5Checksum

def main():
    sha256cs = GCodeSHA256Checksum(".\testsha256.gcode")
    sha256cs.ApplySignature()
    print(sha256cs.VerifySignature("ThisShouldFail"))
    
    md5cs = GCodeMD5Checksum(".\testmd5.gcode")
    md5cs.ApplySignature()
    print(md5cs.VerifySignature("ThisShouldFail"))
    g
if __name__ == "__main__":
    main()
