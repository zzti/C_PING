// iping.cpp : Defines the entry point for the console application.
//

#pragma comment(lib,"ws2_32.lib")
//#pragma pack(4) //�ֽڶ���
#include   "winsock2.h"
#include   "stdlib.h"
#include   "stdio.h"
#include   <time.h>
#include   "string.h"
 
#define ICMP_ECHO	8 //ICMP��������
#define ICMP_ECHOREPLY 0 //ICMP����Ӧ��
#define ICMP_MIN	8 //ICMP���ݰ����Ϊ8���ֽ�
#define DEF_PACKET_SIZE    32   //Ĭ�����ݰ�����
#define DEF_PACKET_NUMBER  4   //Ĭ�Ϸ���ICMP����Ĵ���
#define MAX_PACKET	1024        //���ݰ���󳤶�
 
 
//����IPͷ�� 
typedef struct iphdr
{ 
	unsigned int h_len:4; // ͷ���� 
	unsigned int version:4; // �汾��
	unsigned char tos; // �������� 
	unsigned short total_len; // �ܳ���
	unsigned short ident; // ��ʶ 
	unsigned short frag_and_flags; //��־
	unsigned char ttl; //����ʱ��
	unsigned char proto; // �ϲ�Э�� 
	unsigned short checksum; // У���
	unsigned int sourceIP; //ԴIP
	unsigned int destIP; //Ŀ��IP
}IpHeader; 
 
// ����ICMP ͷ�� 
typedef struct icmphdr 
{ 
	BYTE i_type; //����
	BYTE i_code; //����
	USHORT i_cksum; //У���
	USHORT i_id; //��ʶ
	USHORT i_seq; //���к�
	
	ULONG timestamp; //����
}IcmpHeader; 
 
 
 
 
void fill_icmp_data(char *, int); //���icmp���ݰ�
USHORT checksum(USHORT *, int); //����У���
int decode_resp(char *,int ,struct sockaddr_in *); //�յ����ݺ����
 

void remove_newline(char str[])
{
	char *pos;
	while((pos=strchr(str,'\n')!=NULL)||(pos=strchr(str,'\r')!=NULL)){
		strcpy(pos,pos+1);
	}
}

char* removeNewline(char* str) {
    int length = strlen(str);
    if (length > 0 && ((str[length - 1] == '\n')||(str[length - 1] == '\r') )) {
        str[length - 1] = '\0';
    }
    return str;
}

void showtime(){
	
	time_t currentTime;
    struct tm *localTime;

	 // ��ȡ��ǰ����ʱ��
    time(&currentTime);
    // ת��Ϊ����ʱ��
    localTime = localtime(&currentTime);    
	
    //printf("Current date and time: %s ", removeNewline(asctime(localTime)));

	printf("%s ", removeNewline(asctime(localTime)));
	
}
 
 
void Usage(char *progname)//��ʾ�û��ó���ʹ�÷���
{ 
	printf("Usage:\n"); 
	printf("%s target [number of packets] [data_size]\n",progname); 
	printf("datasize can be up to 1Kb\n"); 
} 
 
 
 
 
void main(int argc, char **argv)
{ 
	WSADATA wsaData; //��ʼ��windows socket��Ҫ�Ĳ���
	SOCKET sockRaw;  //ԭʼ�׽���
	struct sockaddr_in dest,from; //Դ��Ŀ��IP��ַ
	struct hostent * hp; //ָ��ָ���������������ַ�б����Ϣ�Ľṹ��
	int iRecv,iSend, datasize,times; 
	int fromlen = sizeof(from); 
 
 
	int timeout = 1000;  //��ʱʱ��1000ms=1s
	int statistic = 0;  // ����ͳ��  
	char *dest_ip; 
	char *icmp_data; 
	char *recvbuf; 
	unsigned int addr=0; 
	USHORT	seq_no = 0; 
	int		i;
	
	if (WSAStartup(MAKEWORD(2,1),&wsaData) != 0)
	{ 
		printf("WSAStartup failed: %d\n",GetLastError()); 
		return; 
	} 
 
 
	//ʹ�÷�������ʱ��ʾ��ʾ��Ϣ
	if (argc <2 ) 
	{ 
		Usage(argv[0]); 
		return;
	} 
 
 
	//����ԭʼ�׽���
//	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	//ע��Ϊ��ʹ�÷��ͽ��ճ�ʱ����(������SO_RCVTIMEO, SO_SNDTIMEO)��
	//    ���뽫��־λ��ΪWSA_FLAG_OVERLAPPED !
	sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	// ����ԭʼ�׽��ֲ��ɹ�
	if (sockRaw == INVALID_SOCKET)
	{ 
		printf("WSASocket() failed: %d\n", WSAGetLastError()); 
		return; 
	} 
 
 
	//�趨���ͳ�ʱʱ��
	iRecv = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)); 
	if(iRecv == SOCKET_ERROR)
	{ 
		printf("failed to set recv timeout: %d\n",WSAGetLastError()); 
		return; 
	} 
 
 
	//�趨�������ݳ�ʱʱ��
	timeout = 1000; 
	iRecv = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)); 
	if(iRecv == SOCKET_ERROR) { 
		printf("failed to set send timeout: %d\n",WSAGetLastError()); 
		return; 
	} 
 
 
	
	memset(&dest,0,sizeof(dest)); 
 
 
	//�����û������Ŀ���ַ
	hp = gethostbyname(argv[1]); 
	if (!hp)
	{ 
		addr = inet_addr(argv[1]); 
	} 
 
 
	//�Ƿ�����
	if ((!hp) && (addr == INADDR_NONE))
	{ 
		printf("Unable to resolve %s\n",argv[1]); 
		return; 
	} 
 
 
	//��¼Ŀ��������Ϣ�Ľṹ��
	//��ַ
	if (hp != NULL) 
		memcpy(&(dest.sin_addr),hp->h_addr,hp->h_length); 
	else 
		dest.sin_addr.s_addr = addr; 
 
 
	//Э����
	if (hp) 
		dest.sin_family = hp->h_addrtype; 
	else 
		dest.sin_family = AF_INET; 
 
 
 
 
	//Ŀ��IP
	dest_ip = inet_ntoa(dest.sin_addr); 
		
 
 
	//����Ŀ���ַ����������Ping�Ĵ���
	if(argc>2)
	{
		times=atoi(argv[2]);
		if(times == 0)
			 times = DEF_PACKET_NUMBER;
	}
	else
		times = DEF_PACKET_NUMBER;
	
	//�����������ݴ�С
	if (argc >3) 
	{ 
		datasize = atoi(argv[3]); 
 
 
		//������0������Ĭ�����ݰ���С
		if (datasize == 0) 
			datasize = DEF_PACKET_SIZE;
 
 
		//�û����������ݰ���С̫��
		if (datasize >1024)    
		{
			printf("WARNING : data_size is too large !\n");
			datasize = DEF_PACKET_SIZE; 
		}
	} 
	else 
		datasize = DEF_PACKET_SIZE; 
	
	datasize += sizeof(IcmpHeader); 
 
 
	icmp_data = (char *)malloc(MAX_PACKET); 
	recvbuf = (char *)malloc(MAX_PACKET); 
	
	if (!icmp_data)
	{ 
		printf("HeapAlloc failed %d\n",GetLastError()); 
		return; 
	} 
	
	memset(icmp_data, 0, MAX_PACKET); 
 
 
	//���ICMP���ݰ������͡����롢��ʶ��
	fill_icmp_data(icmp_data,datasize); 
 
 
	//��ʾ����pingĿ������
	printf("\nPinging %s ....\n\n",dest_ip);
	
	
 
	//Ping���
	for(i=0; i<times; i++)
	{ 
		//׼��ICMP��ͷ������
		((IcmpHeader *)icmp_data)->i_cksum = 0; 
		//ȡ���Ժ���Ϊ��λ�ļ��������������ʱ����
		((IcmpHeader *)icmp_data)->timestamp = GetTickCount(); 	
		((IcmpHeader *)icmp_data)->i_seq = seq_no++; //���кŵ���
		((IcmpHeader *)icmp_data)->i_cksum = checksum((USHORT*)icmp_data,datasize);//����У���
		
		//����ICMP���ݰ�
		iSend = sendto(sockRaw,icmp_data,datasize,0,(struct sockaddr*)&dest,sizeof(dest)); 
		
		//����ʧ��
		if (iSend == SOCKET_ERROR)
		{ 
			if (WSAGetLastError() == WSAETIMEDOUT) 
			{ 
				showtime();
				printf("Request timed out.\n"); 
				continue; 
			} 
			printf("sendto failed: %d\n",WSAGetLastError()); 
			break; 
		} 
 
 
 
 
		if (iSend < datasize )
		{ 
			printf("Only sent  %d bytes\n",iSend); 
		} 
 
 
 
 
		//����Ӧ������
		iRecv = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen); 
		
		//����ʧ��
		if (iRecv == SOCKET_ERROR)
		{ 
			if (WSAGetLastError() == WSAETIMEDOUT) 
			{ 
				showtime();
				printf("Request timed out.\n"); 
				continue; 
			}

			printf("recvfrom failed: %d\n",WSAGetLastError()); 
			break; 
		} 
 
 
		//�ɹ�����
		if(!decode_resp(recvbuf,iRecv,&from))
			statistic++; //��¼�ɹ�������Ӧ���ݰ��Ĵ���
		
		Sleep(1000); 
	}
 
 
	//ͳ������Ping�����ͳ�ƽ��
	printf("\nPing statistics for %s \n",dest_ip);
	printf("    Packets: Sent = %d,Received = %d, Lost = %d (%2.0f%% loss)\n",times,
			statistic,(times-statistic), (float)(times-statistic)/times*100);
 
 
	free(recvbuf);
	free(icmp_data);
 
 
	closesocket(sockRaw);
	WSACleanup();
 
 
	return; 
} 
 
 
 
 
//�յ���ӦIP���ݰ��󣬶�����н���
int decode_resp(char *buf, int bytes,struct sockaddr_in *from) 
{ 
	IpHeader *iphdr; 
	IcmpHeader *icmphdr; 
	unsigned short iphdrlen; 
	
	iphdr = (IpHeader *)buf; 
	iphdrlen = (iphdr->h_len) * 4 ; //ͷ��ռ�������ֽ� 
	
	if (bytes < iphdrlen + ICMP_MIN)
	{ 
		printf("Too few bytes from %s\n",inet_ntoa(from->sin_addr)); 
	} 
 
 
	//�ҵ�ICMP���ݰ���ʼ�ĵط�
	icmphdr = (IcmpHeader*)(buf + iphdrlen); 
	if (icmphdr->i_type != ICMP_ECHOREPLY)
	{ 
		printf("non-echo type %d recvd\n",icmphdr->i_type); 
		return 1; 
	} 
 
 
	//�ǲ��Ƿ�������������ݰ�
	if (icmphdr->i_id != (USHORT)GetCurrentProcessId()) 
	{ 
		printf("someone else''s packet!\n"); 
		return 1; 
	} 


  showtime();

	printf("%d bytes from %s:", bytes, inet_ntoa(from->sin_addr)); 
	printf(" icmp_seq = %d. ",icmphdr->i_seq); 
	printf(" time: %d ms ", GetTickCount()-icmphdr->timestamp); //���͵����չ��̵ľ�����ʱ��
	printf("\n");
	return 0; 
} 
 
 
//����У���
USHORT checksum(USHORT *buffer, int size) 
{ 
	unsigned long cksum=0; 
	
	while(size >1) { 
		cksum+=*buffer++; 
		size -=sizeof(USHORT); 
	} 
	if(size) { 
		cksum += *(UCHAR*)buffer; 
	} 
	cksum = (cksum >> 16) + (cksum & 0xffff); 
	cksum += (cksum >>16); 
	return (USHORT)(~cksum); 
} 
 
 
//���ICMP���ݰ�
void fill_icmp_data(char * icmp_data, int datasize)
{ 
	IcmpHeader *icmp_hdr; 
	char *datapart; 
	
	icmp_hdr = (IcmpHeader *)icmp_data; 
	icmp_hdr->i_type = ICMP_ECHO; 
	icmp_hdr->i_code = 0; 
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId(); 
	icmp_hdr->i_cksum = 0; 
	icmp_hdr->i_seq = 0; 
	datapart = icmp_data + sizeof(IcmpHeader); 
 
 
	//������������
	memset(datapart,17, datasize - sizeof(IcmpHeader)); 
}