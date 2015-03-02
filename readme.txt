                            VGTFTPD v1.0.

   This is TFTP server which I wrote to allow OS/2 usage as PXE boot server.

Features:
- simple configuration. Even commandline switches are not necessary;
- support of TSIZE and BLKSIZE TFTP options;
- possibility to disable some options;
- verbose mode with detailed descriptions of packets and events;

Restrictions:
- only one connection is possible at time. A next connection attempt silently
  terminates previous connection if it is in progress;
- no write support

Usage:
vgtftpd [-v] [-do blksize] [-do tsize] [-rtimeout <time in seconds>] [-root <root dir>]
Where:
-v - verbose mode;
-do blksize - disable option BLKSIZE support (necessary on some broken PXE 
    firmwares. In particular on Intel Pro 100 with PXE 0.99);
-do tsize - disable option TSIZE support;
-rtimeout <time in seconds> - timeout to wait for client's ACK. After this
    timeout our packet is retransmitted. Default value is 3;
-root <root dir> - path to root dir for TFTP requests. Default value is current dir.

Author:
"Vyacheslav Gnatenko" <moveton@gmail.com>
