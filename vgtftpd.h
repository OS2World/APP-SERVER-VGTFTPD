#include <stdbool.h>
#include <stdint.h>

/**************************** REQUEST TYPE ************************************/
#define RRQ     01                      /* read request              */
#define WRQ     02                      /* write request             */
#define DATA    03                      /* data packet               */
#define ACK     04                      /* acknowledgement           */
#define ERROR   05                      /* error code                */
#define OACK    06                      /* option ack                */
/**************************** REQUEST PACKET STRUCT ***************************/
typedef struct
{
  char filename[80];                   /* filename to be read       */
  char type_trf;                       /* n(etascii),o(ctet),m(ail) */
  bool reqTsize;                       /* is TSIZE requested        */
  long blksize;                        /* -1 not used               */
} TftpRrqPacket;

typedef struct
{
  uint16_t ackBlockNum;                /* ACK block number          */
} TftpAckPacket;

typedef struct
{
  int  rc;                             /* return  code              */
  char msger[80];                      /* error msg                 */
} TftpErrPacket;

typedef struct
{
  uint16_t pktType;
  const char* pktName;
  union
  {
    TftpRrqPacket rrq;
    TftpAckPacket ack;
    TftpErrPacket err;
  };
} TftpPacket;

/* default, minimal and maximum data block size */
#define BLKSIZE_DEFAULT 512
#define BLKSIZE_MIN 8
#define BLKSIZE_MAX 65464
