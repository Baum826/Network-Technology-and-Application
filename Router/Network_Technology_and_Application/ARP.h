#pragma once
#include<iostream>
using namespace std;
//ARP���ݰ�����
#pragma pack(1)    //�����ֽڶ���ģʽ 

//��̫��֡�ײ�
struct Ethernet_Header {
	BYTE DesMAC[6];    //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];    //Դ��ַ
	WORD FrameType;    //֡����
};

//ARP֡
struct ARP_Packet {
	Ethernet_Header FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()    //�ָ�ȱʡ���뷽ʽ