#pragma once
#include<iostream>
using namespace std;
//ARP数据包定义
#pragma pack(1)    //进入字节对齐模式 

//以太网帧首部
struct Ethernet_Header {
	BYTE DesMAC[6];    //目的地址
	BYTE SrcMAC[6];    //源地址
	WORD FrameType;    //帧类型
};

//ARP帧
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
#pragma pack()    //恢复缺省对齐方式