#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os, sys, time, json, random, base64


''' frida '''
from common.friMgr import frida_base_initialize as frida_init




class program_updater:
    
    def __init__(self, process_object, aobscanjs="aobscan.js"):
        self.update_values = { }

        self.cli = frida_init(process_object, aobscanjs)


    def export(self, file_json):
        json.dump(
            self.update_values, open(file_json, "w", encoding="utf-8-sig")
        )
        return


    def scan(self, file_json):
        ''' return bool '''

        cache_data = { }

        values = json.load(
            open(file_json, "r", encoding="utf-8-sig")
        )

        if (not "patterns" in values or 0 == len(values["patterns"])):
            return False

        for pattern in values["patterns"]:
            ''' empty '''
            if (not pattern): continue

            assert( "aob" in pattern and "notes" in pattern and "key" in pattern )

            assert( not pattern["key"] in cache_data )

            ''' dummy: default '''
            cache_data[ pattern["key"] ] = \
                eval(pattern.get("value", 0), None, cache_data)

            ''' append: default '''
            self.update_values[ pattern["key"] ] = { }

            ''' searches '''
            for aob in pattern["aob"]:
                ''' empty '''
                if (not aob): continue

                assert( "pattern" in aob and "mode" in aob and "offset" in aob )

                ''' changed search module '''
                if (aob.get("module", '')): 
                    self.cli.rpc("searchmodule")(aob["module"])
                    ''' append module '''
                    self.update_values[ pattern["key"] ]["module"] = aob["module"]

                ''' eval '''
                offset = eval(aob["offset"], None, cache_data)

                ''' rpc aob-scan '''
                rva = self.cli.rpc("aobscan")({
                    "pattern": aob["pattern"],
                    "mode": aob["mode"],
                    "offset": offset,
                    "notes": pattern["notes"]
                })
                
                ''' not found '''
                if (not rva): continue

                ''' override '''
                cache_data[ pattern["key"] ] = rva

                break

            ''' append value '''
            self.update_values[ pattern["key"] ]["value"] = cache_data[ pattern["key"] ]

        return 0 < len(self.update_values)
