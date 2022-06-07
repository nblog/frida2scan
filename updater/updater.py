#!%SystemDrive%/Python/Python38/python
# -*- coding: utf-8 -*-


import os, sys, time, json, random, base64


''' frida '''
from common.friMgr import frida_base_initialize as frida_init




class program_updater:
    
    def __init__(self, process_object):
        self.update_values = { }

        self.cli = frida_init(process_object,
            os.path.join(os.path.dirname(__file__), "aobscan.js"))


    def export(self, file_json):
        json.dump(
            self.update_values, open(file_json, "w", encoding="utf-8-sig")
        )
        return


    def scan(self, file_json):
        ''' return bool '''

        self.update_values.clear()

        values = json.load(
            open(file_json, "r", encoding="utf-8-sig")
        )

        if (not "patterns" in values or 0 == len(values["patterns"])):
            return False

        for pattern in values["patterns"]:
            assert( "aob" in pattern and "notes" in pattern and "key" in pattern )

            ''' searches '''
            for aob in pattern["aob"]:
                assert( "pattern" in aob and "mode" in aob and "offset" in aob )

                ''' changed search module '''
                if (aob.get("module", '')): self.cli.rpc("searchmodule")(aob["module"])

                ''' eval '''
                offset = eval(aob["offset"], {}, {})

                rva = self.cli.rpc("aobscan")({
                    "pattern": aob["pattern"],
                    "mode": aob["mode"],
                    "offset": offset,
                    "notes": pattern["notes"]
                })

                assert( not pattern["key"] in  self.update_values )

                if (not rva): continue

                self.update_values[ pattern["key"] ] = {
                    "value": "{:#x}".format(rva),
                    "module": aob.get("module", '')
                }

                break
        
        return 0 < len(self.update_values)