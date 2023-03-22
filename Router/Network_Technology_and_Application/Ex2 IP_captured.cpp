#pragma comment(lib,"wpcap.lib")
#include<iostream>
#include<string>
#include"pcap.h"
#include"IP.h"
using namespace std;


int main() {
	pcap_if_t* alldevs;    //ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];    //������Ϣ������

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
		pcap_addr* addr = d->addresses;			//��ȡ������ӿ��豸��IP��ַ��Ϣ

		//�����Ϣ
		cout << "����ӿ��豸:" << name << endl;
		cout << "������Ϣ:" << description << endl;
		cout << "�豸ip��ַ��Ϣ:" << addr << endl;
		cout << endl;
	}

	//�û�������Ҫ�����Ľӿ�
	cout << endl;
	cout << "��ѡ�����������ӿ��豸(��˳���������ּ���):";
	while (1) {
		cin >> request_num;
		if (request_num > dev_num || request_num <= 0)
			cout << "�������!" << endl;
		else {
			break;
		}
	}

	//�������û���Ҫ���豸
	for (d = alldevs; count != request_num; count++) 
		d = d->next;

	//������ӿ�
	pcap_t* hand = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (hand == NULL) {
		cout << "���ӽӿ�ʧ��!" << endl;
		return 0;
	}
	cout << "���ڼ���:" << d->description << endl << endl;

	//�������ݰ�(�������ò���10��)
	//pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **)
	pcap_pkthdr* header;    //pcap_next_ex��һ�����������ڴ洢����ͷ
	const u_char* content;    //pcap_next_ex�ڶ������������ڴ洢��������
	int packet_num, result;    //result�洢�������ݰ����
	for (packet_num = 1; packet_num <= 10; packet_num++) {
		result = pcap_next_ex(hand, &header, &content);    
		 //resultΪ0����ʱ
		if (result == 0) {
			cout << "�������ݰ���ʱ!" << endl;
			continue;
		}
		//resultΪ1������
		else if (result == -1) {
			cout << "�������ݰ�����!" << endl;
			break;
		}
		
		//������ݰ�����ͷ����
		cout << "ʱ���:" << header->ts.tv_sec << endl;
		cout << "���񳤶�:" << header->caplen << endl;
		cout << "���ݰ�����:" << header->len << endl;

		//���õ���������ǿ��ת�������
		IP_Packet* data_packet = (IP_Packet*)content;
		u_char* SrcMAC = data_packet->FrameHeader.SrcMAC;
		u_char* DesMAC = data_packet->FrameHeader.DesMAC;
		BYTE* type = (BYTE*)data_packet->FrameHeader.FrameType;
		//���Դ��ַ
		cout << "ԴMAC��ַ:";
		for (int i = 0; i < 6; i++) 
			printf("%.2x ", SrcMAC[i]);
		cout << endl;

		//���Ŀ�ĵ�ַ
		cout << "Ŀ��MAC��ַ:";
		for (int i = 0; i < 6; i++) 
			printf("%.2x ", DesMAC[i]);
		cout << endl;

		//�������
		cout << "����:";
		for(int i=0;i<=1;i++)
			printf("%.2x", type[i]);   //����type��WORD�ı�ΪBYTE[2]����Ϊֱ�����WORD�����0008����0800�����뷽ʽ��һ��
		cout << endl;
		
		cout << endl;
	}

	//�ͷ��豸�б�
	pcap_freealldevs(alldevs); 
	return 0;
}