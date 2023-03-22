#pragma once
#include<iostream>
using namespace std;

//��̫��֡��IP���ݰ��Ľṹ����
#pragma pack(1)    //�����ֽڶ���ģʽ 

//��̫��֡�ײ�
struct Ethernet_Header {
	BYTE DesMAC[6];    //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];    //Դ��ַ
	WORD FrameType;    //֡����
};

//IP���ݰ�
typedef struct IP_Data {
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
};

//����֡�ײ���IP�ײ�������
typedef struct IP_Packet {
	Ethernet_Header FrameHeader;    //֡�ײ�
	IP_Data IPHeader;    //IP֡
};
#pragma pack()    //�ָ�ȱʡ���뷽ʽ