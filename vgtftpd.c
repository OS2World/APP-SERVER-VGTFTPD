// Very simple TFTPD which can only send files and can be easily crashed by
// incorrect packets. Also it doesn't support multiple connections and sends
// files as is without converting to transfer mode

#include "vgtftpd.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

bool m_argVerbose;
bool m_disOptBlksize;
bool m_disOptTsize;
long m_recvTimeout; // recv() timeout in milliseconds
long m_recvErrTimeout; // timeout for error state in milliseconds
unsigned m_maxTransmitCount;
char m_argPathPrefix[PATH_MAX+1];

typedef const char* PCCHAR;

static uint16_t getU16(const void* buf)
{
  return ntohs(*(uint16_t*)buf);
}

static void setU16(const void* buf, uint16_t val)
{
  *(uint16_t*)buf = htons(val);
}

#define NETPKT_MAX_SIZE 0x10000 // UDP can't exceed this size

typedef struct
{
  size_t size;
  unsigned char octets[NETPKT_MAX_SIZE];
} NetworkPacket;

const char TFTP_OPT_BLKSIZE[] = "blksize";
const char TFTP_OPT_TSIZE[] = "tsize";

static int decode(const NetworkPacket* pNetPkt, TftpPacket* packet)
{
  PCCHAR pos[20];
  int   nbr;

  if (pNetPkt->size < 2)
  {
    printf("Too short packet: %d\n", pNetPkt->size);
    return 1; // too short for type field
  }

  packet->pktType = getU16(pNetPkt->octets);
  const unsigned char* raw = pNetPkt->octets + 2;

  switch(packet->pktType)
  {
  case RRQ:
    packet->pktName = "RRQ";

    nbr        = 0;
    pos[ nbr ] = raw;
  
    for (int i=0; i<pNetPkt->size; i++)
    {
      if (raw[i] == '\0')
      {
        pos[ ++nbr ] = raw + i + 1;
      }
    }
    nbr--;
    strcpy(packet->rrq.filename, pos[0]);

    if (stricmp(pos[1],"octet") == 0)
    {
      packet->rrq.type_trf = 'B';
    }
    else if (stricmp(pos[1],"netascii") == 0)
    {
      packet->rrq.type_trf = 'A';
    }
    else if (stricmp(pos[1],"mail") == 0)
    {
      packet->rrq.type_trf = 'M';
    }
    else
    {
      printf("Unknown transfer type: %s\n", pos[1]);
      return 2;
    }

    packet->rrq.reqTsize = false;
    packet->rrq.blksize = -1;
    for (int i=2; i<nbr; i+=2)
    {
      if (!stricmp(pos[i], TFTP_OPT_TSIZE))
      {
        packet->rrq.reqTsize = true;
      }

      if (!stricmp(pos[i], TFTP_OPT_BLKSIZE))
      {
        packet->rrq.blksize = atol(pos[i+1]);
      }
    }
    break;

  case ERROR:
    packet->pktName = "ERROR";

    packet->err.rc = getU16(raw);
    strcpy(packet->err.msger, raw + 2);
    break;

  case ACK:
    packet->pktName = "ACK";
    packet->ack.ackBlockNum = getU16(raw);
  case WRQ:
    packet->pktName = "WRQ";
  case OACK:
    packet->pktName = "OACK";
    break;
  default:
    printf("Invalid packet type: %u\n", (unsigned)packet->pktType);
    return 2;
  }

  return 0;
}

static void break_handler(int sig_nummer)
{
   printf("TFTPD stopped succesfully\n");
   exit(0);
}

typedef enum
{
  TC_Closed,        // closed connection
  TC_AckOptions,    // waiting for ACK for sent OACK
  TC_AckData,       // waiting for ACK for sent DATA
  TC_Error,         // error is sent. Used to repeat ERROR response
} TftpConnectionState;

typedef struct
{
  int serverSocket; // fixed value after initialization

  // circular buffer:
  // [netPktInd] - last received and answered packet
  // [netPktInd + 1] - last sent packet
  // [netPktInd + 2] - just received packet
  NetworkPacket netPkts[3];
  unsigned netPktInd;
  unsigned transmitCount;

  TftpConnectionState state;

  struct sockaddr_in clientAddr;
  int lenClientAddr;

  long reqBlksize;

  FILE* pFile;
  size_t blockSize;
  uint16_t blockNum;
  bool isLastDataSent;
} TftpConnection;

static void resetConnection(TftpConnection* pConn)
{
  pConn->netPktInd = 0;
  pConn->transmitCount = 0;

  pConn->state = TC_Closed;

  if (pConn->pFile)
  {
    fclose(pConn->pFile);
    pConn->pFile = NULL;
  }

  pConn->blockSize = BLKSIZE_DEFAULT;
  pConn->blockNum = 1;
  pConn->isLastDataSent = false;
}

static inline NetworkPacket* getAnsweredNetPacket(TftpConnection* pConn)
{
  return pConn->netPkts + pConn->netPktInd;
}

static inline NetworkPacket* getSentNetPacket(TftpConnection* pConn)
{
  return pConn->netPkts + ((pConn->netPktInd + 1) % 3);
}

// Start answer packet. Last received packet is assumed to be last answered
// packet after this call
static inline NetworkPacket* takeSendNetPacket(TftpConnection* pConn)
{
  // roll buffer
  pConn->netPktInd = (pConn->netPktInd + 2) % 3;

  return pConn->netPkts + ((pConn->netPktInd + 1) % 3);
}

static inline NetworkPacket* getReceiveNetPacket(TftpConnection* pConn)
{
  return pConn->netPkts + ((pConn->netPktInd + 2) % 3);
}

// send prepared packet
static void sendNetPacket(TftpConnection* pConn, const NetworkPacket* pPkt, bool isRetransmit)
{
  if (isRetransmit)
  {
    ++pConn->transmitCount;
  }
  else
  {
    pConn->transmitCount = 1;
  }

  int ecrit = sendto(pConn->serverSocket, pPkt->octets, pPkt->size, 0,
                     (struct sockaddr *)&(pConn->clientAddr), pConn->lenClientAddr);
  if (ecrit == -1)
  {
    psock_errno("sendto()");
    exit(4);
  }
}

static void sendNumberOACK(TftpConnection* pConn, PCCHAR optName, int optVal)
{
  NetworkPacket* oackPkt = takeSendNetPacket(pConn);

  char* pCh = oackPkt->octets;

  setU16(pCh, OACK);
  pCh += 2;

  size_t len = strlen(optName);
  strcpy(pCh, optName);
  pCh += len + 1;

  len = sprintf(pCh, "%d", optVal);
  pCh += len + 1;

  if (m_argVerbose)
  {
    printf(">> : OACK: %s=%d\n", optName, optVal);
  }

  oackPkt->size = pCh - oackPkt->octets;
  sendNetPacket(pConn, oackPkt, false);
}

static void sendData(TftpConnection* pConn)
{
  NetworkPacket* dataPkt = takeSendNetPacket(pConn);

  setU16(dataPkt->octets, DATA);
  setU16(dataPkt->octets + 2, pConn->blockNum);
  size_t dataLen = fread(dataPkt->octets + 4, 1, pConn->blockSize, pConn->pFile);
  if (m_argVerbose)
  {
    printf(">> : Data block: %u. Data size: %zu\n", (unsigned)pConn->blockNum, dataLen);
  }
  
  dataPkt->size = 4 + dataLen;
  sendNetPacket(pConn, dataPkt, false);

  pConn->isLastDataSent = (dataLen < pConn->blockSize);
  pConn->state = TC_AckData;
}

/**
 * Common error action:
 * - send error packet
 * - place connection to error state to allow it expire
 * - release connection resources except network sockets/buffers
 */
static void doError(TftpConnection* pConn, uint16_t errCode, const char* errText)
{
  if (m_argVerbose)
  {
    printf(">> : Error: (%u) %s\n", (unsigned)errCode, errText);
  }

  NetworkPacket* errPkt = takeSendNetPacket(pConn);
  setU16(errPkt->octets, ERROR);
  setU16(errPkt->octets + 2, errCode);
  strcpy(errPkt->octets + 4, errText);
  errPkt->size = 4 + strlen(errText) + 1;
  sendNetPacket(pConn, errPkt, false);

  pConn->state = TC_Error;

  if (pConn->pFile)
  {
    fclose(pConn->pFile);
    pConn->pFile = NULL;
  }
}

static void processPacketInClosed(TftpConnection* pConn, TftpPacket* pPacket);
static void processPacketInAckOptions(TftpConnection* pConn, TftpPacket* pPacket);
static void processPacketInAckData(TftpConnection* pConn, TftpPacket* pPacket);
static void processPacketInError(TftpConnection* pConn, TftpPacket* pPacket);

static void processPacket(TftpConnection* pConn, TftpPacket* pPacket)
{
  switch (pConn->state)
  {
  case TC_Closed:
    processPacketInClosed(pConn, pPacket);
    break;
  case TC_AckOptions:
    processPacketInAckOptions(pConn, pPacket);
    break;
  case TC_AckData:
    processPacketInAckData(pConn, pPacket);
    break;
  case TC_Error:
    processPacketInError(pConn, pPacket);
    break;
  default:
    printf("!!!Invalid connection state %d!!!\n", (int)pConn->state);
    resetConnection(pConn);
  }
}

static void notifyIgnoredPacket(TftpConnection* pConn, TftpPacket* pPacket)
{
  if (m_argVerbose)
  {
    printf("<< %15s: Ignoring %s\n", inet_ntoa(pConn->clientAddr.sin_addr), pPacket->pktName);
  }
}

static void processPacketInClosed(TftpConnection* pConn, TftpPacket* pPacket)
{
  switch (pPacket->pktType)
  {
  case RRQ:
    {
      if (m_argVerbose)
      {
        printf("<< %15s: Read %s\n", inet_ntoa(pConn->clientAddr.sin_addr), pPacket->rrq.filename);
      }

      printf("RRQ for file '%s' with mode '%c'\n", pPacket->rrq.filename, pPacket->rrq.type_trf);
      
      char filePath[PATH_MAX+1];
      sprintf(filePath, "%s\\%s", m_argPathPrefix, pPacket->rrq.filename);
      pConn->pFile = fopen(filePath, "rb");
      if (!pConn->pFile)
      {
        // file open error. Send error
        printf("File '%s' is not opened\n", filePath);

        char errMsg[500];
        snprintf(errMsg, sizeof(errMsg), "File '%s' is not found", filePath);
        doError(pConn, 1, errMsg);

        // This is special case when we generate error without established
        // connection. So we go to the initial state immediatelly.
        resetConnection(pConn);
        break;
      }

      if (m_disOptTsize)
      {
        pPacket->rrq.reqTsize = false; // configuration forces TSIZE option ignoring
      }

      if (m_disOptBlksize ||
          (pPacket->rrq.blksize < BLKSIZE_MIN) ||
          (pPacket->rrq.blksize > BLKSIZE_MAX))
      {
        // configuration forces BLKSIZE option ignoring or block size is out of
        // valid range
        pPacket->rrq.blksize = -1;
      }

      if (pPacket->rrq.reqTsize || (pPacket->rrq.blksize != -1))
      {
          // some options are requested. We need to send cumulative OACK with
          // values which we agree to use

        // begin OACK packet
        NetworkPacket* oackPkt = takeSendNetPacket(pConn);
        char* pCh = oackPkt->octets;
        setU16(pCh, OACK);
        pCh += 2;

        if (pPacket->rrq.reqTsize)
        {
          if (m_argVerbose)
          {
            printf("Checking stat of '%s'\n", filePath);
          }

          struct stat s_stat;
          if (stat(filePath, &s_stat) != 0)
          {
            printf("    cannot stat %s\n", filePath);

            char errMsg[500];
            snprintf(errMsg, sizeof(errMsg), "Cannot stat %s", filePath);
            doError(pConn, 0, errMsg);

            // This is special case when we generate error without established
            // connection. So we go to the initial state immediatelly.
            resetConnection(pConn);
            break;
          }

          // append OACK info
          size_t len = strlen(TFTP_OPT_TSIZE);
          strcpy(pCh, TFTP_OPT_TSIZE);
          pCh += len + 1;

          len = sprintf(pCh, "%d", (int)s_stat.st_size);
          pCh += len + 1;

          if (m_argVerbose)
          {
            printf(">> : OACK: %s=%d\n", TFTP_OPT_TSIZE, (int)s_stat.st_size);
          }
        }

        if (pPacket->rrq.blksize != -1)
        {
          pConn->blockSize = pPacket->rrq.blksize; // value is already validated. Accept it

          if (m_argVerbose)
          {
            printf("                   :blksize set to :%zu\n", pConn->blockSize);
          }

          // append OACK info
          size_t len = strlen(TFTP_OPT_BLKSIZE);
          strcpy(pCh, TFTP_OPT_BLKSIZE);
          pCh += len + 1;

          len = sprintf(pCh, "%zu", pConn->blockSize);
          pCh += len + 1;

          if (m_argVerbose)
          {
            printf(">> : OACK: %s=%zu\n", TFTP_OPT_BLKSIZE, pConn->blockSize);
          }
        }

        // finish OACK packet and send it
        oackPkt->size = pCh - oackPkt->octets;
        sendNetPacket(pConn, oackPkt, false);
        pConn->state = TC_AckOptions;

        break; // wait for ACK
      }

      sendData(pConn); // no options to confirm. Start data transfer immediatelly
      break;
    }
  default:
    notifyIgnoredPacket(pConn, pPacket);
  }
}

static void processPacketInAckOptions(TftpConnection* pConn, TftpPacket* pPacket)
{
  switch (pPacket->pktType)
  {
  case ACK:
    {
      if (m_argVerbose)
      {
        printf("<< %15s :Ack block :%u\n", inet_ntoa(pConn->clientAddr.sin_addr), (unsigned)pPacket->ack.ackBlockNum);
      }

      if (pPacket->ack.ackBlockNum)
      {
        // OACK ACK is ACK to block 0 so this is not what we are waiting for
        notifyIgnoredPacket(pConn, pPacket);
        break;
      }

      sendData(pConn); // options are negotiated. Starting data transfer
      break;
    }
  default:
    notifyIgnoredPacket(pConn, pPacket);
  }
}

static void processPacketInAckData(TftpConnection* pConn, TftpPacket* pPacket)
{
  switch (pPacket->pktType)
  {
  case ACK:
    {
      if (m_argVerbose)
      {
        printf("<< %15s :Ack block :%u\n", inet_ntoa(pConn->clientAddr.sin_addr), (unsigned)pPacket->ack.ackBlockNum);
      }

      if (pPacket->ack.ackBlockNum != pConn->blockNum)
      {
        if (m_argVerbose)
        {
          printf("Ignoring ackBlockNum=%u because last blockNum=%u\n",
                 (unsigned)pPacket->ack.ackBlockNum, (unsigned)pConn->blockNum);
        }
        break;
      }

      ++pConn->blockNum;

      if (pConn->isLastDataSent)
      {
        if (m_argVerbose)
        {
          printf("Transfer is finished\n");
        }

        resetConnection(pConn); // closing connection on last ACK
      }
      else
      {
        sendData(pConn);
      }
      break;
    }
  default:
    notifyIgnoredPacket(pConn, pPacket);
  }
}

static void processPacketInError(TftpConnection* pConn, TftpPacket* pPacket)
{
    // retransmission requests are not go here. There are no valid actions for
    // other packets so let's ignore them
    notifyIgnoredPacket(pConn, pPacket);
}

static void executeServer(TftpConnection* pConn)
{
  resetConnection(pConn);

  while (1)
  {
    //                 Timeouts and retransmition policy.
    //
    // There are three use cases to support:
    // 1) No connection is active. This means no saved retransmissions and
    // recv() may wait forever;
    // 2) Connection is in progress and so we are waiting for ACK from the
    // remote. recv() waits for m_recvTimeout and retransmits. Also retransmit
    // is executed if remote send us the same packet to which we already
    // answered. We assume that our previously sent packet was lost. Max
    // transmit count of the same packet is m_maxTransmitCount.
    // 3) Connection is in error state. We wait for m_recvErrTimeout and
    // terminate connection. During this time remote may rerequest the error
    // answer by sending the same packet. Such answer will be retransmitted the
    // same way as in (2) but this transmit will not reset timeout so
    // m_recvErrTimeout is total time when error state is active.

    // will be filled in recv() loop
    struct sockaddr_in clientAddr;
    int lenClientAddr;

    NetworkPacket* recPkt = getReceiveNetPacket(pConn);
    clock_t recvStartTime = clock(); // on OS/2 Watcom C it is system monotonic clock. NON PORTABLE
    while (1) // recv() loop
    {
      long recvTimeout;
      if (pConn->state == TC_Closed)
      {
        recvTimeout = -1; // no connection, indefinite wait
      }
      else
      {
        long fullTimeout = (pConn->state == TC_Error) ? m_recvErrTimeout : m_recvTimeout;

        recvTimeout = fullTimeout - (clock() - recvStartTime);
        if (recvTimeout < 0)
        {
          // timeout occured while handling of previous packet. Let's give last
          // chance to remote and check for a new packet without waiting
          recvTimeout = 0;
        }
      }

      int selSockets[1];
      selSockets[0] = pConn->serverSocket;
      int selReadyCount = os2_select(selSockets, 1, 0, 0, recvTimeout);
      if (selReadyCount == -1)
      {
        psock_errno("os2_select()");
        resetConnection(pConn);
        return;
      }

      if (selReadyCount == 0)
      {
        // timed out
        if (pConn->state == TC_Error)
        {
          if (m_argVerbose)
          {
            // log only on verbose. This is normal situation because we can exit
            // error state only by timeout
            printf("ErrorTimeout done. Resetting connection\n");
          }
          resetConnection(pConn);
        }
        else if (pConn->transmitCount < m_maxTransmitCount)
        {
          if (m_argVerbose)
          {
            printf(">> : retransmiting answer by timeout\n");
          }

          sendNetPacket(pConn, getSentNetPacket(pConn), true);
          recvStartTime = clock(); // start full timeout again
        }
        else
        {
          if (pConn->state != TC_Error)
          {
            printf("Timed out and transmit count exceeded. Resetting connection\n");
          }
          resetConnection(pConn);
        }

        continue; // anyway loop because we have no data
      }

      lenClientAddr = sizeof(clientAddr);
      int inPktSize = recvfrom(pConn->serverSocket, recPkt->octets, sizeof(recPkt->octets),
                               0, (struct sockaddr *)&clientAddr, &lenClientAddr);
      if (inPktSize == -1)
      {
        psock_errno("recvfrom()");
        resetConnection(pConn);
        return;
      }
      recPkt->size = inPktSize; // complete recPkt filling

      if (m_argVerbose)
      {
        printf("< %15s: Got UDP packet. Size=%zu\n",
               inet_ntoa(pConn->clientAddr.sin_addr),
               (unsigned)recPkt->size);
      }

      if (pConn->state != TC_Closed)
      {
        // compare only known fields because lenClientAddr may include garbage part of struct sockaddr
        if ((lenClientAddr != pConn->lenClientAddr) ||
            (clientAddr.sin_addr.s_addr != pConn->clientAddr.sin_addr.s_addr) ||
            (clientAddr.sin_port != pConn->clientAddr.sin_port))
        {
          char oldIpStr[16];
          strcpy(oldIpStr, inet_ntoa(pConn->clientAddr.sin_addr));
          char newIpStr[16];
          strcpy(newIpStr, inet_ntoa(clientAddr.sin_addr));
          printf("Unexpected remote address change %s:%u(%d) -> %s:%u(%d). Resetting connection\n",
                 oldIpStr, (unsigned)ntohs(pConn->clientAddr.sin_port), pConn->lenClientAddr,
                 newIpStr, (unsigned)ntohs(clientAddr.sin_port), lenClientAddr);
          resetConnection(pConn);
          // not loop. Attempt to handle the packet on closed connection
        }
        else
        {
          // Confirmed that it is not first packet in the connection. Possibly it
          // is retransmit of the previous packet because remote doesn't receive
          // our answer. In this case we need to resend the last answer.
          NetworkPacket* ansPkt = getAnsweredNetPacket(pConn);
          if ((recPkt->size == ansPkt->size) &&
              !memcmp(recPkt->octets, ansPkt->octets, recPkt->size))
          {
            if (pConn->transmitCount < m_maxTransmitCount)
            {
              if (m_argVerbose)
              {
                printf(">> : retransmiting answer by request\n");
              }

              sendNetPacket(pConn, getSentNetPacket(pConn), true);
              if (pConn->state != TC_Error)
              {
                recvStartTime = clock(); // start full timeout again but not in error state
              }
              continue; // loop recv()
            }
            else
            {
              printf("Retransmit requested but transmit count exceeded. Resetting connection\n");
              resetConnection(pConn);
              // not loop. Attempt to handle the packet on closed connection
            }
          }
        }
      }

      break;
    }

    TftpPacket packet;
    int decodeErr = decode(recPkt, &packet);
    if (decodeErr)
    {
      continue; // ignore error packet
    }

    if (packet.pktType == ERROR)
    {
      if (pConn->state != TC_Closed)
      {
        if (m_argVerbose)
        {
          printf("<< %15s :Error rc = %d msger = %s\n",
                 inet_ntoa(clientAddr.sin_addr), packet.err.rc, packet.err.msger);
        }
        else
        {
          printf("                Error --> %s\n", packet.err.msger);
        }

        resetConnection(pConn);
      }

      continue; // nothing more to process
    }

    if (pConn->state == TC_Closed)
    {
      if ((packet.pktType != RRQ) && (packet.pktType != WRQ))
      {
        printf("Ignoring not RRQ/WRQ packet on closed connection\n");
        continue;
      }

      // begin connection
      memcpy(&(pConn->clientAddr), &clientAddr, lenClientAddr);
      pConn->lenClientAddr = lenClientAddr;
    }

    processPacket(pConn, &packet);
  }
}

static void exitPrintUsage(const char* name)
{
  if (!name)
  {
    name = "<vgtftpd>";
  }

  printf("Usage: %s [-v] [-do blksize] [-do tsize] [-rtimeout <time in seconds>] [-root <root dir>]\n", name);
  exit(1);
}

int main(int argc, char** argv)
{
  setvbuf(stdout, NULL, _IOLBF, 1024);

  signal(SIGINT, break_handler);

  printf("********************************************\n");
  printf("*  TFTP Server (TFTPD)                     *\n");
  printf("*  Support blksize, tsize options          *\n");
  printf("*  Version: %s %s           *\n", __DATE__, __TIME__);
  printf("*  (C) Copyright Vyacheslav Gnatenko 2011  *\n");
  printf("********************************************\n");
  printf("\n");

  m_argVerbose = false;
  m_disOptBlksize = false;
  m_disOptTsize = false;
  strcpy(m_argPathPrefix, ".");
  m_recvTimeout = 3000;
  m_maxTransmitCount = 4;

  for(int i=1; i<argc; i++)
  {
    if (!strcmp(argv[i], "-v"))
    {
      m_argVerbose = true;
      continue;
    }

    if (!strcmp(argv[i], "-do"))
    {
      ++i;
      if (i >= argc)
      {
        exitPrintUsage(argv[0]);
      }

      if (!strcmp(argv[i], "blksize"))
      {
        m_disOptBlksize = true;
        continue;
      }

      if (!strcmp(argv[i], "tsize"))
      {
        m_disOptTsize = true;
        continue;
      }

      exitPrintUsage(argv[0]);
    }

    if (!strcmp(argv[i], "-root"))
    {
      ++i;
      if (i >= argc)
      {
        exitPrintUsage(argv[0]);
      }
      strcpy(m_argPathPrefix, argv[i]);
      continue;
    }

    if (!strcmp(argv[i], "-rtimeout"))
    {
      ++i;
      if (i >= argc)
      {
        exitPrintUsage(argv[0]);
      }

      m_recvTimeout = atol(argv[i]);
      if (m_recvTimeout < 1)
      {
        m_recvTimeout = 1;
      }
      m_recvTimeout *= 1000; // convert to milliseconds
      continue;
    }

    exitPrintUsage(argv[0]);
  }

  m_recvErrTimeout = 2 * m_recvTimeout;

  int serverSocket;
  {
    serverSocket = socket(PF_INET, SOCK_DGRAM, 0);
    if (serverSocket == -1)
    {
        psock_errno("server socket()");
        exit(1);
    }
   
    struct servent* tftpd_prot = getservbyname("tftp", "udp");
    if (tftpd_prot == NULL)
    {
      printf("The tftpd/udp protocol is not listed in the etc/services file\n");
      exit(1);
    }
   
    struct sockaddr_in server;
    server.sin_family      = AF_INET;
    server.sin_port        = tftpd_prot->s_port;
    server.sin_addr.s_addr = INADDR_ANY;
   
    if (bind(serverSocket, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
      psock_errno("server bind()");
      exit(2);
    }
  }

  TftpConnection* pConn = (TftpConnection*)malloc(sizeof(TftpConnection));
  if (!pConn)
  {
    fprintf(stderr, "No memory for connection\n");
    exit(2);
  }

  pConn->serverSocket = serverSocket;

  executeServer(pConn);

  soclose(serverSocket);
  return 0;
}
