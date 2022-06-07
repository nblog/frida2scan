# -*- coding: utf-8 -*-


import os, sys, collections


# https://frida.re/docs/javascript-api
import frida


class fridaError(Exception):
    ''' '''



class frida_base_initialize:

    friProcess = collections.namedtuple("friProcess", ["name", "pid", "parameters"])

    '''

    '''
    @staticmethod
    def enumerate_processes():
        return [ frida_base_initialize.friProcess(process.name.lower(), process.pid, process.parameters) \
            for process in frida.get_local_device().enumerate_processes() ]


    def cleanup(self):
        try:
            self.unload_script(), self.detach_session()
        finally:
            self.session = self.script = self.msg_cb = None
            self.proc_id, self.proc_name, self.proc_params = 0, '', []

            self.dev = frida.get_local_device()

    __del__ = cleanup


    '''

    '''
    def __init__(self, process_object, script_file='', msg_cb=None, proc_cwd=''):
        #
        self.cleanup()
        
        self.set_message_callback(msg_cb)

        created_ = False
        if (isinstance(process_object, int)):
            self.proc_id = process_object
        elif (isinstance(process_object, str)):
            self.proc_name = process_object
            self.proc_id = self.dev.get_process(self.proc_name).pid
        elif (isinstance(process_object, (list, tuple))):
            self.proc_name, self.proc_params = process_object[0], process_object[1:]
            created_ = self.process_create(process_object, proc_cwd)

        self.process_attach(self.proc_id)

        if (script_file and os.path.exists(script_file)):
            self.load_script_file(script_file)
        
        if (created_): self.process_resume(self.proc_id)


    '''

    '''
    def on_message(self, message, data):
        if "send" == message["type"]:
            if (self.msg_cb): self.msg_cb(message["payload"], data)
        elif "error" == message["type"]:
            raise fridaError("\n{}".format(message["stack"]))


    '''

    '''
    def unload_script(self):
        if ( hasattr(self, "script") and self.script ): 
            self.script.unload()


    '''

    '''
    def load_script(self, script_code):
        self.script = self.session.create_script(script_code)
        self.script.on("message", self.on_message)
        self.script.load()


    '''

    '''
    def load_script_file(self, script_path):
        self.load_script( \
            open(script_path, "r", encoding="utf-8-sig").read())


    '''

    '''
    def detach_session(self):
        if ( hasattr(self, "session") and self.session ):
            self.session.detach()


    '''

    '''
    def process_attach(self, proc_id):
        self.session = self.dev.attach(proc_id)


    '''

    '''
    def process_resume(self, proc_id):
        self.dev.resume(proc_id)


    '''

    '''
    def process_create(self, proc_cmd, proc_cwd):
        assert(os.path.exists(proc_cmd[0]))
        self.proc_id = \
            self.dev.spawn(proc_cmd[0], \
                argv = proc_cmd, \
                cwd = proc_cwd if (proc_cwd) else os.path.dirname(proc_cmd[0])
            )
        return 0 < int(self.proc_id)


    '''

    '''
    def rpc(self, export):
        assert( export in self.script.list_exports() )
        return getattr(self.script.exports, export)


    '''

    '''
    def post_message(self, message, **kwargs):
        return self.script.post(message, **kwargs)


    '''

    '''
    def set_message_callback(self, msg_cb):
        self.msg_cb = msg_cb


    '''

    '''
    def ptrlength(self):
        self.load_script('''
rpc.exports = {
    ptrlength: function() {
        return Process.pointerSize;
    },
}
''')
        length = int(self.rpc("ptrlength")())
        self.unload_script()
        return length

    '''

    '''
    def process_name(self):
        self.load_script('''
rpc.exports = {
    procname: function() {
        return Process.enumerateModules()[0].path;
    },
}
''')
        procname = str(self.rpc("procname")())
        self.unload_script()
        return procname

    '''

    '''
    def process_command(self):
        assert("win32" == sys.platform)
        self.load_script('''
rpc.exports = {
    cmdline: function() {
        // https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew
        const GetCommandLineW = new NativeFunction(Module.getExportByName("kernel32.dll", "GetCommandLineW"), 
        "pointer", [ ]);
        return GetCommandLineW().readUtf16String();
    },
}
''')
        cmdline = str(self.rpc("cmdline")())
        self.unload_script()
        return cmdline


    @property
    def process_id(self):
        return self.proc_id
