Applesoft BASIC Decompiler
==========================

applebasic.py
-------------

A tool for decompiling (or detokenizing) assembled Applesoft BASIC files into the original-ish text.

You will need to extract the BASIC files from an Apple II disk image using a tool such as `CiderPress II <https://ciderpress2.com>`_.

varinspector.py
---------------

A tool for extracting the BASIC variable table from a raw Apple II memory dump.

In AppleWin, you can dump the memory to a file by opening the debugger (magnifying glass icon) and typing::
   
    bsave "mem.dump",0:0000:ffff

In MAME, you can dump the memory by starting the emulator in debug mode, e.g.::

    mame apple2e -debug -flop1 oregonmod_a.do

Then when ready, run the following command inside the debugger window::

    save mem.dump,0x0000,0x10000
