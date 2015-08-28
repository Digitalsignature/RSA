/**********************************************************************
* RSA library.
* version: 1.5
*
* July, 5th, 2015
*
* This lib was written by DucThang
* Contact:thangdn.tlu@outlook.com
*
* Every comment would be appreciated.
*
* If you want to use parts of any code of mine:
* let me know and
* use it!
**********************************************************************
generate_RSA_Key("thang.pem");
gen_public_RSA_Key("thang.pem","thang1.pem");
decryptRSA(fileText,file RSA(pub/pri),fileOuput);
encryptRSA(fileText,file RSA(pub/pri),fileOuput);
**********************************************************************/

#ifndef RSA_H
#define RSA_H
#include "../PrGlib.h"
#include "Base64.h"
#include "ASN1.h"
#include <NTL/ZZ.h>
#include <gmpxx.h>
#include <string>
#include <iostream>
#include <time.h>
#include <fstream>
using namespace std;
using namespace NTL;
#define KEY 128
typedef ZZZ mpz_class;

string convert_hexa(string a)
{
    string b;
    ZZZ ma;
    for(int i=0;i<a.length();i+=8)
    {
        string maa=a.substr(i,8);
        if(maa.length()!=8)break;
        ma.set_str(maa,2);
        maa=ma.get_str(16);
        if(maa.length()==1)maa="0"+maa;
        b+=maa;
    }
    return b;
}

void generate_RSA_Key(char *filePrivateKey)
{
    PrGlib thang;
    thang.PrG_set_size(3072);
    thang.PrG_renew();
    /*Generate p and q as strong primes */
    ZZZ p=thang.PrG_generate_strong_prime();

    thang.PrG_renew();

    ZZZ q=thang.PrG_generate_strong_prime();

    if(p>q)
    {
        ZZZ ma=p;
        p=q;
        q=ma;
    }
    ZZZ n=q*p;
    ZZZ phi=(p^1)*(q^1);
    ZZZ e=65537;
    /*Find e such that gcd(e,phi)=1*/

    /*******************************/
    /*Compute d= e^-1 mod n*/
    ZZZ d;
    mpz_invert(d.get_mpz_t(),e.get_mpz_t(),phi.get_mpz_t());

    //PEM
    RSA_Key keys;
    keys.modulu_n=n;
    keys.Version=0;
    keys.prime_p=p;
    keys.prime_q=q;
    keys.privateExponent_d=d;
    keys.publicExponent_e=e;
    keys.exponent_p=d%(p-1);
    keys.exponent_q=d%(q-1);
    mpz_invert(keys.coefficient.get_mpz_t(),p.get_mpz_t(),q.get_mpz_t());
    //(inverse of q) mod p
    ZZZ xua;
    xua.set_str(privatePEMEN(keys),16);
    ofstream pem(filePrivateKey);
    string a=base64_encode("00"+xua.get_str(2));
    pem<<"-----BEGIN RSA PRIVATE KEY-----"<<endl;
    for(int i=1;i<=a.length();i++)
    {
        pem<<a[i-1];
        if(i%64==0&&i!=0&&i!=a.length())pem<<endl;
    }
    pem<<endl<<"-----END RSA PRIVATE KEY-----";
    pem.close();
}
void gen_public_RSA_Key(char * filepem,char *filename)
{
    ifstream pem(filepem);
    if(!filepem)return;
    string code,a;
    while(!pem.eof())
    {
        getline(pem,a);
        if(a=="-----BEGIN RSA PRIVATE KEY-----")
        {  getline(pem,a);
            do{
                    code+=a;
                getline(pem,a);
            }while(a!="-----END RSA PRIVATE KEY-----");
        }

    }

    code=base64_decode(code);
    code=convert_hexa(code);
    RSA_Key b=privatePEMDE(code);
    /*************************************/
    ZZZ xua;xua.set_str(publicPEMEN(b),16);
    ofstream pem1(filename);
     a=base64_encode("00"+xua.get_str(2));
    pem1<<"-----BEGIN PUBLIC KEY-----"<<endl;
    for(int i=1;i<=a.length();i++)
    {
        pem1<<a[i-1];
        if(i%64==0&&i!=0&&i!=a.length())pem1<<endl;
    }
    pem1<<endl<<"-----END PUBLIC KEY-----";
    pem1.close();

}

void decryptRSA (char* fileText,char* RSAKey,bool isPrivateKey, char *fileDecrypt)
{
    ifstream filetext(fileText);
    ofstream decrypt(fileDecrypt);
    ifstream pem(RSAKey);
     if(!pem){
        cout<<"Fail!publicKey.txt isn't exist";
        return;
    }
    if(!filetext){
        cout<<"Fail!filetext.txt isn't exist";
        return;
    }
    if(isPrivateKey)
    {
        string code,a;
        while(!pem.eof())
        {
            getline(pem,a);
            if(a=="-----BEGIN RSA PRIVATE KEY-----")
            {  getline(pem,a);
                do{
                        code+=a;
                    getline(pem,a);
                }while(a!="-----END RSA PRIVATE KEY-----");
            }

        }

        code=base64_decode(code);
        code=convert_hexa(code);
        RSA_Key b=privatePEMDE(code);
        /**********************/
        /*read text from fileText*/
        //filetext>>a;
        string file;
        while(!filetext.eof())
        {
            getline(filetext,a);
            file+=a;
        }
        ZZZ codes;
        /*decrypto base64 to bits*/
        codes.set_str(base64_decode(file),2);

        /*M=C^d mode n*/
        mpz_powm(codes.get_mpz_t(),codes.get_mpz_t(),b.privateExponent_d.get_mpz_t(),b.modulu_n.get_mpz_t());
        /*convert to bit and crop length of KEY{128,192,256}*/
        a=codes.get_str(2);
        a=a.substr(2048-KEY,KEY);
        /********************/
        codes.set_str(a,2);
        decrypt<<codes.get_str();
    }else{
        string code,a;
        while(!pem.eof())
        {
            getline(pem,a);
            if(a=="-----BEGIN PUBLIC KEY-----")
            {  getline(pem,a);
                do{
                        code+=a;
                    getline(pem,a);
                }while(a!="-----END PUBLIC KEY-----");
            }

        }

        code=base64_decode(code);
        code=convert_hexa(code);
        RSA_Public_Key b=publicPEMDE(code);
        /**********************/
        string file;
        while(!filetext.eof())
        {
            getline(filetext,a);
            file+=a;
        }
        ZZZ codes;
        /*decrypto base64 to bits*/
        codes.set_str(base64_decode(file),2);
        /*M=C^d mode n*/
        mpz_powm(codes.get_mpz_t(),codes.get_mpz_t(),b.publicExponent_e.get_mpz_t(),b.modulu_n.get_mpz_t());
        /*convert to bit and crop length of KEY{128,192,256}*/
        a=codes.get_str(2);
        a=a.substr(2048-KEY,KEY);
        /********************/
        codes.set_str(a,2);
        decrypt<<codes.get_str();
    }

    filetext.close();
    decrypt.close();
    pem.close();
}
void cryptRSA (char* fileText,char* RSAKey,bool isPrivateKey,char *fileCrypt,string headCode="1000010010000100")
{
    ifstream filetext(fileText);
    ifstream pem(RSAKey);
    ofstream filecrypt(fileCrypt);
    if(!filetext){
        cout<<"Fail!Filetext isn't exist";
        return;
    }
    if(!pem){
        cout<<"Fail!Filekey isn't exist";
        return;
    }
    /*read key from fileKey*/
    if(isPrivateKey)
    {
        string code,a;
        while(!pem.eof())
        {
            getline(pem,a);
            if(a=="-----BEGIN RSA PRIVATE KEY-----")
            {  getline(pem,a);
                do{
                        code+=a;
                    getline(pem,a);
                }while(a!="-----END RSA PRIVATE KEY-----");
            }

        }

        code=base64_decode(code);
        code=convert_hexa(code);
        RSA_Key b=privatePEMDE(code);

        /*linked head16bit with bit random + KEY{128,192,256}*/
        string TEXT=headCode;
        ZZ numbersite;
        RandomBits(numbersite,(2032-KEY));
        stringstream buffer;
        buffer<<numbersite;
        ZZZ codes;
        codes=buffer.str();
        int strlen=codes.get_str(2).length();
        for(;strlen<2032-KEY;strlen++)TEXT+='1';
        TEXT+=codes.get_str(2);
        filetext>>headCode;
        codes=headCode;
        TEXT+=codes.get_str(2);
        /*********************/
        /*C=M^e mod n*/
        codes.set_str(TEXT,2);
        mpz_powm(codes.get_mpz_t(),codes.get_mpz_t(),b.privateExponent_d.get_mpz_t(),b.modulu_n.get_mpz_t());
        string ba=codes.get_str(2);
        int leng=ba.length()%6;
        for(int i=0;i<6-leng;i++)
        {
            ba='0'+ba;
        }

        ba=base64_encode(ba);
        for(int i=1;i<=ba.length();i++)
        {
            filecrypt<<ba[i-1];
            if(i%64==0&&i!=0&&i!=ba.length())filecrypt<<endl;
        }

    }else{
        string code,a;
        while(!pem.eof())
        {
            getline(pem,a);
            if(a=="-----BEGIN PUBLIC KEY-----")
            {  getline(pem,a);
                do{
                        code+=a;
                    getline(pem,a);
                }while(a!="-----END PUBLIC KEY-----");
            }

        }

        code=base64_decode(code);
        code=convert_hexa(code);
        RSA_Public_Key b=publicPEMDE(code);

        /*linked head16bit with bit random + KEY{128,192,256}*/
        string TEXT=headCode;
        ZZ numbersite;
        RandomBits(numbersite,(2032-KEY));
        stringstream buffer;
        buffer<<numbersite;
        ZZZ codes;
        codes=buffer.str();
        int strlen=codes.get_str(2).length();
        for(;strlen<2032-KEY;strlen++)TEXT+='1';
        TEXT+=codes.get_str(2);
        filetext>>headCode;
        codes=headCode;
        TEXT+=codes.get_str(2);
        /*********************/
        /*C=M^e mod n*/
        codes.set_str(TEXT,2);
        mpz_powm(codes.get_mpz_t(),codes.get_mpz_t(),b.publicExponent_e.get_mpz_t(),b.modulu_n.get_mpz_t());
        string ba=codes.get_str(2);
        int leng=ba.length()%6;
        for(int i=0;i<6-leng;i++)
        {
            ba='0'+ba;
        }
        ba=base64_encode(ba);
        for(int i=1;i<=ba.length();i++)
        {
            filecrypt<<ba[i-1];
            if(i%64==0&&i!=0&&i!=ba.length())filecrypt<<endl;
        }
    }

    filecrypt.close();
    filetext.close();
    pem.close();
}

#endif // RSA_H
