#!%SystemDrive%/Python/Python38/python
# -*- coding: utf-8 -*-




if __name__ == "__main__":

    from updater.updater import program_updater


    cli = "example.exe" # or pid

    updater = program_updater(cli)

    if (updater.scan("update_example.json")):
        updater.export("export.json")

    print("done")