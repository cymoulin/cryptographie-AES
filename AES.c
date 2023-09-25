//
//  AES.c
//
//  Created by Cyrille Moulin on 14/04/2016.
//  Copyright © 2016 Cyrille Moulin. All rights reserved.
//


#include "AES.h"


/****** SubBytes
        Lecture dans le tableau SubByteTab. */


void SubBytes(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = SubByteTab[state[i%4][i/4]];
    }
}


/****** InvSubBytes
        Lecture dans le tableau InvSubByteTab. */


void InvSubBytes(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = InvSubByteTab[state[i%4][i/4]];
    }
}


/****** Recopie un tableau de 4*4 octets, un "état", dans un autre.
 */


void CopyAtoB(byte A[4][4] , byte B[4][4]) {
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            B[i][j] = A[i][j];
        }
    }
}


/**************** ShiftRows and InvShiftRows ******************************/



/****** Applique ShiftRows à l'état sIn et écrit le résultat dans sOut. */


void ShiftRows(byte sIn[4][4], byte sOut[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = sIn[i][(i+j) % 4];
        }
    }
}


/****** Applique InvShiftRows à l'état sIn et écrit le résultat dans sOut. */


void InvShiftRows(byte sIn[4][4], byte sOut[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = sIn[i][(-i+4+j) % 4];
        }
    }
}


/**************** MixColumns and InvMixColumns ******************************/


/****** Applique MixColumns à l'état sIn et écrit le résultat dans sOut. */


void MixColumns(byte sIn[4][4], byte sOut[4][4]) {
    
    static byte m[4][4] = {
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2 };
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                sOut[i][j] = sOut[i][j] ^ mulGF256Tab[256*m[i][k] + sIn[k][j]];
            }
        }
    }
}


/****** Applique InvMixColumns à l'état sIn et écrit le résultat dans sOut. */


void InvMixColumns(byte sIn[4][4], byte sOut[4][4]) {
    
    static byte m[4][4] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e };
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                sOut[i][j] = sOut[i][j] ^ mulGF256Tab[256*m[i][k] + sIn[k][j]];
            }
        }
    }
}



/***************** KeyExpansion *****************************/

byte Rc[10];        // table construite par initRc
byte Rcon[4*10];    // table construite par initRcon



/****** Clé étendue utilisée pour crypter et décrypter.
        Est construite par keyExpansion(). */

byte W[4*Nb*(Nr+1)];


/****** Construction des tables Rc et Rcon. */


void InitRc() {
    Rc[0] = 1;
    for (int i = 1; i < 10; i++) {
        Rc[i] = mulGF256Tab[256*Rc[i-1] + 0x02];
    }
}


void InitRcon() {
    InitRc();
    for (int i = 0; i < 4*10; i++) {
        if (i%4 == 0) {Rcon[i] = Rc[i/4];} else {Rcon[i] = 0;}
    }
}


/****** Permutation circulaire à gauche des octets d'un mot. */


void RotWord(byte w[4]) {
    byte temp = w[0];
    for (int i = 0; i < 3; i++) {
        w[i] = w[i+1];
    }
    w[3] = temp;
}


/****** SubWord: Applique SubByte à chacun des 4 octets d'un mot. */


void SubWord(byte w[4]) {
    for (int i = 0; i < 4; i++) {
        w[i] = SubByteTab[w[i]];
    }
}


/****** Fabrication de la clé étendue. */


void KeyExpansion(byte k[4*Nk]) {
    byte temp[4];
    int i = 0;
    
    InitRcon();
    
    while (i < 4*Nk) {
        W[i] = k[i];
        i++;
    }
    while (i < 4*Nb*(Nr+1)) {
        for (int j = 0; j < 4; j++) {
            temp[j] = W[i-4+j];
        }
        if (i % (4*Nk) == 0) {
            RotWord(temp);
            SubWord(temp);
            for (int j = 0; j < 4; j++) {
                temp[j] = temp[j] ^ Rcon[i/(1*Nk) + j - 4];
            }
        } else {
            if ((Nk > 6) && (i % (4*Nk) == 16)) {SubWord(temp); }
        }
        for (int j = 0; j < 4; j++) {
            W[i+j] = W[i-4*Nk+j] ^ temp[j];
        }
        i = i + 4;
    }
}


/***************** Chiffrement et Déchiffrement d'un état ***********/


/****** Applique AddRoundKey à sIn, le résultat se trouve dans sIn. */

void AddRoundKey(byte sIn[4][4], byte w[]){
    for (int i = 0; i < 4*Nb; i++) {
        sIn[i%4][i/4] = (sIn[i%4][i/4] ^ w[i]);
    }
}


/****** L'état in[] est chiffré, le résultat est dans out[]. */


void Cipher(byte in[4][Nb], byte out[4][Nb]) {
    
    AddRoundKey(in, W);
    
    for (int round = 1; round < Nr; round++) {
        SubBytes(in);
        ShiftRows(in, out);
        MixColumns(out, in);
        AddRoundKey(in, &W[4*Nb*round]);
    }
    
    SubBytes(in);
    ShiftRows(in, out);
    AddRoundKey(out, &W[4*Nb*Nr]);
}


/****** L'état in est déchiffré, le résultat est dans out. */


void Decipher(byte in[4][4], byte out[4][4]) {
    
    AddRoundKey(in, &W[4*Nb*Nr]);
    
    for (int round = Nr-1; round > 0; round--) {
        InvShiftRows(in, out);
        InvSubBytes(out);
        AddRoundKey(out, &W[4*Nb*round]);
        InvMixColumns(out, in);
    }
    InvShiftRows(in, out);
    InvSubBytes(out);
    AddRoundKey(out, W);
}


/****** Chiffrement et Déchiffrement d'un fichier, version 2. */


#define MAX_SIZE_FILE  2048000

byte Alice[MAX_SIZE_FILE], AliceOut[MAX_SIZE_FILE], AliceOutOut[MAX_SIZE_FILE];

size_t tabSize;


/****** Le fichier à crypter est mis dans le tableau tab[] et
        complété par des blancs pour que sa taille soit un multiple de 16.
        On peut aussi y mettre un fichier à décrypter. */


int FileInTabVersion2(char *fnameIn, byte tab[]) {
    FILE *in;
    
    if ((in = fopen(fnameIn, "rb")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    
    size_t size = fread(tab, 1, MAX_SIZE_FILE, in);
    
    while (size%16 != 0) {
        tab[size++] = ' ';
    }
    
    tabSize = size;
    fclose(in);
    return 0;
}


/****** Écrit le contenu du tableau byte tab[] dans un fichier fnameOut. */


int TabInFileVersion2(byte tab[], char *fnameOut) {
    FILE *out;
    if ((out = fopen(fnameOut, "wb")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    fwrite(tab, 1, tabSize, out);
    fclose(out);
    return 0;
}


/****** Chiffrement du tableau tabIn[] avec la clé k[].
        Le résultat se trouve dans le tableau tabOut[]. */


int codageAES2( byte tabIn[], byte k[4*Nk], byte tabOut[]) {
    byte sIn[4][Nb], sOut[4][Nb];
    
    KeyExpansion(k);
    int j = 0, l = 0;
    
    while (j < tabSize) {
        for (int i = 0; i < 16; i++) {
            sIn[i%4][i/4] = tabIn[j++];
        }
        Cipher(sIn, sOut);
        for (int i = 0; i < 16; i++) {
            tabOut[l++] = sOut[i%4][i/4];
        }
    }
    return 0;
}


/****** Déchiffrement du tableau tabIn[] avec la clé k[].
        Le résultat se trouve dans le tableau tabOut[]. */


int decodageAES2(byte tabIn[], byte k[4*Nk], byte tabOut[]) {
    byte sIn[4][Nb], sOut[4][Nb];
    KeyExpansion(k);
    
    int j = 0, l = 0;
    while (j < tabSize) {
        for (int i = 0; i < 16; i++) {
            sIn[i%4][i/4] = tabIn[j++];
        }
        Decipher(sIn, sOut);
        for (int i = 0; i < 16; i++) {
            tabOut[l++] = sOut[i%4][i/4];
        }
    }
    return 0;
}


/***************** main ***********************/


void message() {
    printf("\nPour crypter le fichier \"truc\":\n");
    printf("./test \"encrypt\" \"truc\"\n");
    printf("Le fichier crypté sera nommé: \"truc.encrypted\"\n\n");
    printf("Pour décrypter le fichier \"truc\":\n");
    printf("./test \"decrypt\" \"truc\"\n");
    printf("Le fichier décrypté sera nommé: \"truc.decrypted\"\n\n");
    printf("Exemple:\n");
    printf("./test \"encrypt\" \"Alice.txt\"\n");
    printf("./test \"decrypt\" \"Alice.txt.encrypted\"\n\n");
}


int main(int argc,  char * argv[]) {
    
    if (argc == 3) {
        char s[100];
        
        if (strcmp(argv[1], "encrypt") == 0) {
            strcpy(s, argv[2]);
            strcat(s, ".encrypted");
            FileInTabVersion2(argv[2], Alice);
            codageAES2(Alice, key128, AliceOut);
            TabInFileVersion2(AliceOut, s);
        } else {
            if (strcmp(argv[1], "decrypt") == 0) {
                strcpy(s, argv[2]);
                strcat(s, ".decrypted");
                FileInTabVersion2(argv[2], Alice);
                decodageAES2(Alice, key128, AliceOut);
                TabInFileVersion2(AliceOut, s);
            } else {
                message();
            }
        }
    } else message();
    
    return EXIT_SUCCESS;
}
