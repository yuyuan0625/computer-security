#include<iostream>
#include <string>
#include <stdlib.h> 
#include <stdio.h>
#include <math.h>		//�n�εL����i��ceil 
#include <algorithm>	//�ݭnsort 
using namespace std;

int key_len = 0;	//key������ 
int plain_len = 0;	
int cipher_len = 0;	
int key[100]= {0};	//�x�skey 
int key_index[100] = {0};	//�x�skey��index 
string plain;	 
string cipher;
char en_arr[100][100] = {'X'};	//encrypt�Ψ쪺array 
char de_arr[100][100] = {'X'};	//decrypt�Ψ쪺array 

void init()	//init en_arr and de_arr
{
	for(int i = 0; i < 100; i++)
	{
		for(int j = 0; j < 100; j++)
		{
			en_arr[i][j]= 'X';
			de_arr[i][j]= 'X';
		}
	}
}

int get_key(){	
	string str;
	int cnt = 0;
	cout << "key = ";
	getline(cin, str);
	for (int i = 0; i < str.length(); i++)
	{
		if (str[i] != ' ')
		{
			int tmp = str[i] - '0';	//�Nchar��int�A�s�Jkey[] 
			key[cnt] = tmp;
			//�s�C��key��index��(��ɭԴN�i�H�̧�print cipher/�scipher)
			key_index[tmp-1] = cnt;	
			cnt++;
		}
	}
	key_len = cnt;
	
	sort(key, key + key_len);	//sort 
	int check = 0;
	for (int i = 0; i < key_len - 1; i++)	//check �O�_������key 
	{	
		if(key[i] == key[i+1])
		{
			//cout << "duplicate key!" << endl;	
			check = 1;
		} 
	}
	return check;
}

void get_plain(){
	string str;
	int cnt = 0;
	cout << "plain = ";
	getline(cin, str);
	for (int i = 0; i < str.length(); i++)
	{
		if (str[i] != ' ')
		{
			plain[cnt] = str[i];
			cnt++;
		}
	}
	
	plain_len = cnt;
}

void get_cipher(){
	string str;
	int cnt = 0;
	
	cout << "cipher = ";
	getline(cin, str);
	for (int i = 0; i < str.length(); i++)
	{
		if (str[i] != ' ')
		{
			cipher[cnt] = str[i];
			cnt++;
		}
	}
	cipher_len = cnt;
}

void encrypt(){
 	int row = ceil(float(plain_len)/key_len);	//�L����i�� 
 	//�[�K�L�{ 
 	for(int i = 0; i < row; i++)	//row
 	{
 		for(int j = 0; j < key_len ; j++)	//column
 		{
 			if(j+i*key_len < plain_len)	//�Nplain�s�J(�̷�row�s) 
 			{
 				en_arr[j][i] = plain[j+i*key_len];
 				//cout << en_arr[j][i] << " ";
			}
		}
		//cout << endl;
	}
	
	cout << "cipher:";
	for(int i = 0; i < key_len; i++)
	{
		for(int j = 0; j < row; j++)
		{
			cout << en_arr[key_index[i]][j];
		}
	}
	cout << endl;
 	
}

void decrypt()
{
	int row = ceil(float(cipher_len)/key_len);
	for(int i = 0; i < key_len; i++)
	{
		for(int j = 0; j < row; j++)
		{
			de_arr[key_index[i]][j] = cipher[i * row + j];
		}
	}
	
	cout << "plain: ";
	for(int i = 0; i < row; i++)
	{
		for(int j = 0; j < key_len; j++)
		{
			cout << de_arr[j][i];
		}
	}
	cout << endl;
}

int main()
{
	char ch = '\0';
	while(1){
		init();
		cout << "encrypt: e; decrypt: d; quit: q\n";
		cin>> ch;
		cin.get();	//Ū������ 
		if(ch=='e')
		{
			int check = 0;
			check = get_key();
			while(check == 1)
			{
				cout << "duplicate key, please again" << endl;
				check = get_key();	
			}
			get_plain();
			encrypt();	
		}		
		else if(ch=='d')
		{
			int check = 0;
			check = get_key();
			while(check == 1)
			{
				cout << "duplicate key, please again" << endl;
				check = get_key();	
			}
			get_cipher();	
			decrypt();
		}
		else if(ch == 'q')
			break;
	}
}

