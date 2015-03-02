call ow19env.cmd

set DBGFLAGS=-d0 -ox
if "%1"="debug" set DBGFLAGS=-d2
wcl386 %DBGFLAGS% -we -za99 -bc -fp6 -l=OS2V2 -fe=vgtftpd.exe vgtftpd.c
