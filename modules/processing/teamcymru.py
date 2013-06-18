# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import socket

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError

class TeamCymru (Processing):
        """Gets antivirus status from teamcymru.com."""

        def run(self):
            """Run analysis.
            @return: the number of engines that detected as a malware.
            """
            self.key = "teamcymru"
            response = 'NO_DATA'
            if self.task["category"] == "file":
                if not os.path.exists(self.file_path):
                    raise CuckooProcessingError("File {0} not found, skip".format(self.file_path))

                md5_hash = File(self.file_path).get_md5()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("hash.cymru.com", 43))
                sock.send(md5_hash + "\r\n")
                while True:
                    d = sock.recv(4096)
                    response += d
                    if d == '':
                        break
                sock.close()
                response = response.split(" ")[2].split("\n")[0]
            if response != "NO_DATA":
                return "%s%%" % response
            else:
                return response
