///<reference path='index.d.ts'/>


const ptrlength = Process.pointerSize;

let m = Process.enumerateModules()[0];


let addr_transform = {

    rva: function(addr) {
        return ptr(addr).sub(m.base);
    },

    call: function(addr) {
        let absValue = addr_transform.rva(addr).add(
            addr_transform.value_u32( addr.add(1) )
        ).add(5) ;
        return Number(absValue) & 0xffffffff;
    },

    imm: function(addr) {
        let absValue = addr_transform.value_u32(addr);
        return 4 == ptrlength ? absValue : 
            Number( addr_transform.rva(addr).add(absValue).add(4) );
    },


    value_u8: function(addr) {
        return ptr(addr).readU8();
    },

    value_u16: function(addr) {
        return ptr(addr).readU16();
    },

    value_u32: function(addr) {
        return ptr(addr).readU32();
    },

    value_u64: function(addr) {
        return ptr(addr).readU64();
    },

} 


rpc.exports = {

    searchmodule: function(moduleName) {
        m = Process.getModuleByName(moduleName);
        console.log("module adjustment to:\n" + JSON.stringify(m));
    },

    /**
     * 
     * @param aobinfo { "pattern": "90 90 90 90", "type": "rva", "offset": 0, "notes": "hello" }
     * @returns return hit address
     */
    aobscan: function(aobinfo) {

        if (!("pattern" in aobinfo && "type" in aobinfo && "offset" in aobinfo && "notes" in aobinfo)) {
            console.log("parameter abnormal.\n" + JSON.stringify(aobinfo));
            return Number(0);
        }

        const retValue = Memory.scanSync(m.base, m.size, aobinfo.pattern);

        if (0 < retValue.length) {

            if (1 < retValue.length) {
                console.log( "[" + aobinfo.notes + "]" + " " + "multiple items");
            }
            
            let addr = ptr(retValue[0].address).add(Number(aobinfo.offset));

            const fntransform = addr_transform[aobinfo.type];

            return Number(fntransform(addr));
        }
        else {
            console.log( "[" + aobinfo.notes + "]" + " " + "no data found");
        }

        return Number(0);
    },
    
};