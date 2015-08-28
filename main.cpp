#include <iostream>
#include "PrGlib.h"
#include "RSA.h"
#include "AES-CBC.h"

using namespace std;
#define _TIME int starts,finishs;
#define STARTS_TIME starts=clock();
#define FINISHS_TIME finishs=clock(); cout<<(double)(finishs-starts)/CLOCKS_PER_SEC<<endl;
int main()
{
    //generate_RSA_Key("thang.pem");
    //gen_public_RSA_Key("thang.pem","thang1.pem");
    cryptRSA("text.txt","thang1.pem",0,"cry.txt");
    decryptRSA("cry.txt","thang.pem",1,"decry.txt");
}
