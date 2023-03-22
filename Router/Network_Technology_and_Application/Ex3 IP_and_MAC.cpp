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
	pcap_if_t* alldevs;    //ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	pcap_addr_t* a;
	bool flag = false;
	char errbuf[PCAP_ERRBUF_SIZE];    //������Ϣ������
	vector<string> ip_address_set;


	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1) {    //������
		cout << "Error! Can't get information!" << endl;
	}

	int dev_num = 0;    //�����豸��Ŀ
	int request_num, count = 1;    //request_numΪ�û����룬Ҫ�󲶻�ڼ����豸�����ݰ���count���ڴ��豸�����б������ж��Ƿ񵽴��û�Ҫ����豸


	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		dev_num++;
		string name = d->name;		//����d->name��ȡ������ӿ��豸������
		string description = d->description;		//����d->description��ȡ������ӿ��豸��������Ϣ


		//�����Ϣ
		cout << "�豸����:" << name << endl;
		cout << "������Ϣ:" << description << endl;
		

		//��ȡ������ӿ��豸��IP��ַ��Ϣ
		for (a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				flag = true;
				printf("%s%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				ip_address_set.push_back(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			}
		}
		if(flag == false)
			ip_address_set.push_back("û��IPv4��ַ");
		flag = false;
		cout << endl;
	}


	//�û�������Ҫ�����Ľӿ�
	cout << endl;
	cout << "������ѡ�������:";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "�������!" << endl;
		else {
			break;
		}
	}

	cout << "====================================================================================================" << endl;

	//�������û���Ҫ���豸
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

	cout << "��ѡ�豸ipΪ:" << listening_ip << endl;


	//������ӿ�
	pcap_t* hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "����ʧ��!" << endl;
		return 0;
	}
	cout << "���ڼ���:" << d->description << endl;


	//����������������ѡ�������͵�ARP֡
	ARP_Packet First_Packet;

	//ARPFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC����Ϊ***��������***��MAC��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.FrameHeader.SrcMAC[i] = 0x0f;

	//֡����ΪARP
	First_Packet.FrameHeader.FrameType = htons(0x0806);

	//Ӳ������Ϊ��̫��
	First_Packet.HardwareType = htons(0x0001);

	//Э������ΪIP
	First_Packet.ProtocolType = htons(0x0800);

	//Ӳ����ַ����Ϊ6
	First_Packet.HLen = 6;

	//Э���ַ����Ϊ4
	First_Packet.PLen = 4;

	//����ΪARP����
	First_Packet.Operation = htons(0x0001);

	//��SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		First_Packet.SendHa[i] = 0x0f;

	//��SendIP����Ϊ***��������***�󶨵�IP��ַ
	First_Packet.SendIP = inet_addr("192.192.192.192");

	//��RecvHa����Ϊ0��Ŀ��δ֪��
	for (int i = 0; i < 6; i++)
		First_Packet.RecvHa[i] = 0;

	//��RecvIP����Ϊ�����IP��ַ
	First_Packet.RecvIP = inet_addr(listening_ip.c_str());


	//����ARP��
	pcap_sendpacket(hand, (u_char*)&First_Packet, sizeof(ARP_Packet));

	//����Ҫ����Ļظ���
	ARP_Packet* First_Packet_Reply;

	//����ظ�������ȡѡȡ������MAC��ַ
	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//ǿ������ת��
			First_Packet_Reply = (ARP_Packet*)content;
			if (First_Packet_Reply->RecvIP == inet_addr("192.192.192.192")) {    //ARP����
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (First_Packet_Reply->FrameHeader.DesMAC[i] != First_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//��׽���İ���ԴMACӦ������������MAC��ַ
				if (compare_flag) {
					cout << "MAC��ַΪ:";
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
	cout << "����Ŀ��ip��ַ:";
	cin >> target_ip;


	//��ȡĿ��ip��MAC��ַ

	//����ARP֡
	ARP_Packet Second_Packet;

	//ARPFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		Second_Packet.FrameHeader.DesMAC[i] = 0xff;

	//ARPFrame.FrameHeader.SrcMAC����Ϊ***��������***��MAC��ַ
	for (int i = 0; i < 6; i++)
		Second_Packet.FrameHeader.SrcMAC[i] = First_Packet_Reply->FrameHeader.SrcMAC[i];

	//֡����ΪARP
	Second_Packet.FrameHeader.FrameType = htons(0x0806);

	//Ӳ������Ϊ��̫��
	Second_Packet.HardwareType = htons(0x0001);

	//Э������ΪIP
	Second_Packet.ProtocolType = htons(0x0800);

	//Ӳ����ַ����Ϊ6
	Second_Packet.HLen = 6;

	//Э���ַ����Ϊ4
	Second_Packet.PLen = 4;

	//����ΪARP����
	Second_Packet.Operation = htons(0x0001);

	//��SendHa����Ϊѡȡ������MAC��ַ
	for (int i = 0; i < 6; i++)
		Second_Packet.SendHa[i] = First_Packet_Reply->SendHa[i];

	//��SendIP����Ϊѡȡ�����󶨵�IP��ַ
	Second_Packet.SendIP = inet_addr(listening_ip.c_str());

	//��RecvHa����Ϊ0��Ŀ��δ֪��
	for (int i = 0; i < 6; i++)
		Second_Packet.RecvHa[i] = 0;

	//��RecvIP����Ϊ�����IP��ַ
	Second_Packet.RecvIP = inet_addr(target_ip.c_str());



	//����ARP��
	pcap_sendpacket(hand, (u_char*)&Second_Packet, sizeof(ARP_Packet));
	
	//����Ҫ����Ļظ���
	ARP_Packet* Second_Packet_Reply;

	while (1) {
		pcap_pkthdr* header;
		const u_char* content;
		int result = pcap_next_ex(hand, &header, &content);
		if (result == 1) {
			//ǿ������ת��
			Second_Packet_Reply = (ARP_Packet*)content;
			if (Second_Packet_Reply->SendIP == inet_addr(target_ip.c_str())) {    //ARP����
				bool compare_flag = true;
				for (int i = 0; i < 6; i++)
					if (Second_Packet_Reply->FrameHeader.DesMAC[i] != Second_Packet.FrameHeader.SrcMAC[i]) {
						compare_flag = false;
						break;
					}

				//��׽���İ���ԴMACӦ������������MAC��ַ
				if (compare_flag) {
					cout << "MAC��ַΪ:";
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

	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
	return 0;
}