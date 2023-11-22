#include <stdio.h>

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//======================= Common Functions =======================
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

unsigned char RCON[2]={0x80,0b00110000};
unsigned char nibbleSbox[17]={0x09,0x04,0x0A,0x0B,0x0D,0x01,0x08,0x05,0x06,0x02,0x00,0x03,0x0C,0x0E,0x0F,0x07};

void expand (unsigned char key[2],int round)
{
    unsigned char N0=(key[1]>>4)&0x0F;
    unsigned char N1=key[1]&0x0F;
    
    N0=nibbleSbox[N0]&0x0F;
    N1=nibbleSbox[N1]&0x0F;

    unsigned char w_=((N1<<4)^N0)&0xFF;
    RCON[round-1]&=0xFF;

    key[0]=(key[0]^RCON[round-1]^w_)&0xFF;
    key[0]&=0xFF;
    key[1]=(key[1]^key[0])&0xFF;
   
}

void shiftrows(unsigned char state[4])
{
    unsigned char temp=state[1];
    state[1]=state[3];
    state[3]=temp;
}

void AddRoundKey (unsigned char key[2],unsigned char state[4])
{
    state[0]=state[0]^((key[0]>>4)&0x0F);
    state[1]=state[1]^(key[0]&0x0F);
    state[2]=state[2]^((key[1]>>4)&0x0F);
    state[3]=state[3]^(key[1]&0x0F);
    
}
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//======================= Encryption =============================
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

unsigned char four[16]={0x00,0x04,0x08,0x0C,0x03,0x07,0x0B,0x0F,0x06,0x02,0x0E,0x0A,0x05,0x01,0x0D,0x09};


void mixcloumn(unsigned char state[4]){
    unsigned char s00=state[0];
    unsigned char s10=state[1];
    unsigned char s01=state[2];
    unsigned char s11=state[3];

    unsigned char s00_ =((1*s00)^(four[s10]));
    unsigned char s10_ =((four[s00])^(1*s10));
    unsigned char s01_ =((1*s01)^(four[s11]));
    unsigned char s11_ =((1*s11)^(four[s01]));
    
    state[0]=s00_;
    state[1]=s10_;
    state[2]=s01_;
    state[3]=s11_;
}
void nibbleForword(unsigned char state[4])
{
    state[0]=nibbleSbox[state[0]];
    state[1]=nibbleSbox[state[1]];
    state[2]=nibbleSbox[state[2]];
    state[3]=nibbleSbox[state[3]];

}


void round0_ENC(unsigned char key[2],unsigned char state[4])
{
    AddRoundKey(key,state);
    expand(key,1);
}
void round1_ENC(unsigned char key[2],unsigned char state[4])
{
    nibbleForword(state);
    shiftrows(state);
    mixcloumn(state);
    AddRoundKey(key,state);
    expand(key,2);
}

void round2_ENC(unsigned char key[2],unsigned char state[4])
{
    nibbleForword(state);
    shiftrows(state);
    AddRoundKey(key,state);
}

void AES_Encrypt(unsigned char key[2],unsigned char state[4])
{
    round0_ENC(key,state);
    round1_ENC(key,state);
    round2_ENC(key,state);
}


//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//======================= Decryption =============================
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
unsigned char nibbleSboxInverse[17]={0x0A,0x05,0x09,0x0B,0x01,0x07,0x08,0x0F,0x06,0x00,0x02,0x03,0x0C,0x04,0x0D,0x0E};
unsigned char two[16]={0x00,0x02,0x04,0x06,0x08,0x0A,0x0C,0x0E,0x03,0x01,0x07,0x05,0x0B,0x09,0x0F,0x0D};
unsigned char nine[16]={0x00,0x09,0x01,0x08,0x02,0x0B,0x03,0x0A,0x04,0x0D,0x05,0x0C,0x06,0x0F,0x07,0x0E};


void round0_DEC(unsigned char key2[2],unsigned char state[4])
{
    AddRoundKey(key2,state);
}

void nibbleInverse(unsigned char state[4])
{
    state[0]=nibbleSboxInverse[state[0]];
    state[1]=nibbleSboxInverse[state[1]];
    state[2]=nibbleSboxInverse[state[2]];
    state[3]=nibbleSboxInverse[state[3]];

}

void mixcloumnInverse(unsigned char state[4]){
    unsigned char s00=state[0];
    unsigned char s10=state[1];
    unsigned char s01=state[2];
    unsigned char s11=state[3];

    unsigned char s00_ =((nine[s00])^(two[s10]));
    unsigned char s10_ =((two[s00])^(nine[s10]));
    unsigned char s01_ =((nine[s01])^(two[s11]));
    unsigned char s11_ =((two[s01])^(nine[s11]));
    
    state[0]=s00_;
    state[1]=s10_;
    state[2]=s01_;
    state[3]=s11_;
}


void round1_DEC(unsigned char key1[2],unsigned char state[4])
{

    shiftrows(state);
    nibbleInverse(state);
    AddRoundKey(key1,state);
    mixcloumnInverse(state);
}

void round2_DEC(unsigned char key0[2],unsigned char state[4])
{

    shiftrows(state);
    nibbleInverse(state);
    AddRoundKey(key0,state);
}

void AES_Decrypt(unsigned char key[2],unsigned char state[4])
{
    unsigned char key0[2]={key[0],key[1]};
    unsigned char key1[2]={key[0],key[1]};
    expand(key1,1);
    unsigned char key2[2]={key1[0],key1[1]};
    expand(key2,2);

    round0_DEC(key2,state);
    round1_DEC(key1,state);
    round2_DEC(key0,state);

}


//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//======================= Application ===========================
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////


void main()
{
    unsigned char state[4]={0x08,0x09,0x0A,0x08};//89A8
    unsigned char key[2]={0xAB,0x89};


    AES_Decrypt(key,state);

    printf("%X%X%X%X",state[0],state[1],state[2],state[3]);
}

//unsigned char state[4]={0x00,0x07,0x03,0x08};//89A8
//unsigned char key[2]={0xA7,0x3B};
