#pragma comment(lib,"wpcap.lib")
#include<iostream>
#include<string>
#include"pcap.h"
#include"IP.h"
using namespace std;


int main() {
	pcap_if_t* alldevs;    //指向设备链表首部的指针
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];    //错误信息缓冲区

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
		pcap_addr* addr = d->addresses;			//获取该网络接口设备的IP地址信息

		//输出信息
		cout << "网络接口设备:" << name << endl;
		cout << "描述信息:" << description << endl;
		cout << "设备ip地址信息:" << addr << endl;
		cout << endl;
	}

	//用户输入想要监听的接口
	cout << endl;
	cout << "请选择监听的网络接口设备(按顺序输入数字即可):";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "输入错误!" << endl;
		else {
			break;
		}
	}

	//遍历到用户需要的设备
	for (d = alldevs; count != request_num; count++) 
		d = d->next;

	//打开网络接口
	pcap_t* hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "连接接口失败!" << endl;
		return 0;
	}
	cout << "正在监听:" << d->description << endl << endl;

	//捕获数据包(这里设置捕获10个)
	//pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **)
	pcap_pkthdr* header;    //pcap_next_ex第一个参数，用于存储报文头
	const u_char* content;    //pcap_next_ex第二个参数，用于存储报文内容
	int packet_num, result;    //result存储捕获数据包情况
	for (packet_num = 1; packet_num <= 10; packet_num++) {
		result = pcap_next_ex(hand, &header, &content);    
		 //result为0，超时
		if (result == 0) {
			cout << "捕获数据包超时!" << endl;
			continue;
		}
		//result为1，错误
		else if (result == -1) {
			cout << "捕获数据包错误!" << endl;
			break;
		}
		
		//输出数据包报文头内容
		cout << "时间戳:" << header->ts.tv_sec << endl;
		cout << "捕获长度:" << header->caplen << endl;
		cout << "数据包长度:" << header->len << endl;

		//将得到报文内容强制转换并输出
		IP_Packet* data_packet = (IP_Packet*)content;
		u_char* SrcMAC = data_packet->FrameHeader.SrcMAC;
		u_char* DesMAC = data_packet->FrameHeader.DesMAC;
		BYTE* type = (BYTE*)data_packet->FrameHeader.FrameType;
		//输出源地址
		cout << "源MAC地址:";
		for (int i = 0; i < 6; i++) 
			printf("%.2x ", SrcMAC[i]);
		cout << endl;

		//输出目的地址
		cout << "目的MAC地址:";
		for (int i = 0; i < 6; i++) 
			printf("%.2x ", DesMAC[i]);
		cout << endl;

		//输出类型
		cout << "类型:";
		for(int i=0;i<=1;i++)
			printf("%.2x", type[i]);   //这里type由WORD改变为BYTE[2]，因为直接输出WORD会输出0008而非0800，对齐方式不一致
		cout << endl;
		
		cout << endl;
	}

	//释放设备列表
	pcap_freealldevs(alldevs); 
	return 0;
}