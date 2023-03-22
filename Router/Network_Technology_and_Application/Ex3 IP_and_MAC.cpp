#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include<iostream>
#include<string>
#include<ws2tcpip.h>
#include<winsock2.h>
#include<winsock.h>
#include"pcap.h"
#include"ARP.h"
#include<vector>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
using namespace std;


int main() {
	pcap_if_t* alldevs;    //指向设备链表首部的指针
	pcap_if_t* d;
	pcap_addr_t* a;
	bool flag = false;
	char errbuf[PCAP_ERRBUF_SIZE];    //错误信息缓冲区
	vector<string> ip_address_set;


	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1) {    //错误处理
		cout << "Error! Can't get information!" << endl;
	}

	int dev_num = 0;    //计算设备数目
	int request_num, count = 1;    //request_num为用户输入，要求捕获第几个设备的数据包；count用于从设备链表中遍历，判断是否到达用户要求的设备


	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev_num++;
		string name = d->name;		//利用d->name获取该网络接口设备的名字
		string description = d->description;		//利用d->description获取该网络接口设备的描述信息


		//输出信息
		cout << "设备名称:" << name << endl;
		cout << "描述信息:" << description << endl;
		

		//获取该网络接口设备的IP地址信息
		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				flag = true;
				printf("%s%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ip_address_set.push_back(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			}
		}
		if(flag == false)
			ip_address_set.push_back("没有IPv4地址");
		flag = false;
		cout << endl;
	}


	//用户输入想要监听的接口
	cout << endl;
	cout << "输入你选择的网卡:";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "输入错误!" << endl;
		else {
			break;
		}
	}

	cout << "====================================================================================================" << endl;

	//遍历到用户需要的设备
	for (d = alldevs; count != request_num; count++)
		d = d->next;
	
	int p = 0;
	string listening_ip;
	for (auto it = ip_address_set.begin(); ; it++) {
		p++;
		if (p != request_num)
			continue;
		else {
			listening_ip = *it;
			break;
		}
	}

	cout << "所选设备ip为:" << listening_ip << endl;


	//打开网络接口
	pcap_t* hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "连接失败!" << endl;
		return 0;
	}
	cout << "正在监听:" << d->description << endl;


	//构造虚拟主机向所选网卡发送的ARP帧
	ARP_Packet First_Packet;

	//ARPFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC设置为***虚拟主机***的MAC地址
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.SrcMAC[i] = 0x0f;

	//帧类型为ARP
	First_Packet.FrameHeader.FrameType = htons(0x0806);

	//硬件类型为以太网
	First_Packet.HardwareType = htons(0x0001);

	//协议类型为IP
	First_Packet.ProtocolType = htons(0x0800);

	//硬件地址长度为6
	First_Packet.HLen = 6;

	//协议地址长度为4
	First_Packet.PLen = 4;

	//操作为ARP请求
	First_Packet.Operation = htons(0x0001);

	//将SendHa设置为虚拟主机的MAC地址
	for (int i = 0; i < 6; i++)
		First_Packet.SendHa[i] = 0x0f;

	//将SendIP设置为***虚拟主机***绑定的IP地址
	First_Packet.SendIP = inet_addr("192.192.192.192");

	//将RecvHa设置为0（目标未知）
	for (int i = 0; i < 6; i++)
		First_Packet.RecvHa[i] = 0;

	//将RecvIP设置为请求的IP地址
	First_Packet.RecvIP = inet_addr(listening_ip.c_str());


	//发送ARP包
	pcap_sendpacket(hand, (u_char*)&First_Packet, sizeof(ARP_Packet));

	//声明要捕获的回复包
	ARP_Packet* First_Packet_Reply;

	//捕获回复包，获取选取网卡的MAC地址
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//强制类型转换
			First_Packet_Reply = (ARP_Packet*)content;
			if (First_Packet_Reply->RecvIP == inet_addr("192.192.192.192")) {    //ARP类型
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (First_Packet_Reply->FrameHeader.DesMAC[i] != First_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//捕捉到的包的源MAC应是虚拟主机的MAC地址
				if (compare_flag) {
					cout << "MAC地址为:";
					for (int i = 0; i < 5; i++) {
						printf("%02x:", First_Packet_Reply->FrameHeader.SrcMAC[i]);
					}
					printf("%02x", First_Packet_Reply->FrameHeader.SrcMAC[5]);
					break;
				}
			}
		}
	}
	cout << endl;
	cout << "====================================================================================================" << endl;

	string target_ip;
	cout << "输入目的ip地址:";
	cin >> target_ip;


	//获取目的ip的MAC地址

	//构造ARP帧
	ARP_Packet Second_Packet;

	//ARPFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		Second_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC设置为***虚拟主机***的MAC地址
	for (int i = 0; i < 6; i++)
		Second_Packet.FrameHeader.SrcMAC[i] = First_Packet_Reply->FrameHeader.SrcMAC[i];

	//帧类型为ARP
	Second_Packet.FrameHeader.FrameType = htons(0x0806);

	//硬件类型为以太网
	Second_Packet.HardwareType = htons(0x0001);

	//协议类型为IP
	Second_Packet.ProtocolType = htons(0x0800);

	//硬件地址长度为6
	Second_Packet.HLen = 6;

	//协议地址长度为4
	Second_Packet.PLen = 4;

	//操作为ARP请求
	Second_Packet.Operation = htons(0x0001);

	//将SendHa设置为选取网卡的MAC地址
	for (int i = 0; i < 6; i++)
		Second_Packet.SendHa[i] = First_Packet_Reply->SendHa[i];

	//将SendIP设置为选取网卡绑定的IP地址
	Second_Packet.SendIP = inet_addr(listening_ip.c_str());

	//将RecvHa设置为0（目标未知）
	for (int i = 0; i < 6; i++)
		Second_Packet.RecvHa[i] = 0;

	//将RecvIP设置为输入的IP地址
	Second_Packet.RecvIP = inet_addr(target_ip.c_str());



	//发送ARP包
	pcap_sendpacket(hand, (u_char*)&Second_Packet, sizeof(ARP_Packet));
	
	//声明要捕获的回复包
	ARP_Packet* Second_Packet_Reply;

	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//强制类型转换
			Second_Packet_Reply = (ARP_Packet*)content;
			if (Second_Packet_Reply->SendIP == inet_addr(target_ip.c_str())) {    //ARP类型
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (Second_Packet_Reply->FrameHeader.DesMAC[i] != Second_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//捕捉到的包的源MAC应是虚拟主机的MAC地址
				if (compare_flag) {
					cout << "MAC地址为:";
					for (int i = 0; i < 5; i++) {
						printf("%02x:", Second_Packet_Reply->FrameHeader.SrcMAC[i]);
					}
					printf("%02x", Second_Packet_Reply->FrameHeader.SrcMAC[5]);
					break;
				}
			}
		}
	}
	cout << endl;
	cout << "====================================================================================================" << endl;

	//释放设备列表
	pcap_freealldevs(alldevs);
	return 0;
}