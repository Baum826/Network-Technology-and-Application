#pragma once
#include<iostream>
using namespace std;

//以太网帧和IP数据包的结构定义
#pragma pack(1)    //进入字节对齐模式 

//以太网帧首部
struct Ethernet_Header {
	BYTE DesMAC[6];    //目的地址
	BYTE SrcMAC[6];    //源地址
	WORD FrameType;    //帧类型
};

//IP数据包
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

//包含帧首部和IP首部的数据
typedef struct IP_Packet {
	Ethernet_Header FrameHeader;    //帧首部
	IP_Data IPHeader;    //IP帧
};
#pragma pack()    //恢复缺省对齐方式