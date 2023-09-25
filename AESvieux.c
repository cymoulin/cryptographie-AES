//
//  main.c
//  AES
//
//  Created by Cyrille Moulin on 14/04/2016.
//  Copyright © 2016 Cyrille Moulin. All rights reserved.
//


#include "AES.h"


/********  Multiplication dans le corps à 256 éléments ********************
 A servi à produire la table de multiplication dans GF256 (mulGF256Tab).
 N'est plus utilisée.
*/


byte mulGF256Vieux(byte a, byte b) {
    byte pol = 0b00011011; // 0x1B
    byte res = 0;
    
    while (b != 0) {
        if (b % 2 == 1) {
            res = res ^ a;
        }
        if (a < 128) {a = a << 1;}
        else { a = (a << 1) ^ pol;};
        b = b >> 1;
    }
    return res;
}


/******** Calcul de a^n dans le corps à 256 éléments  ********************
          N'est plus utilisée.
*/


byte powGF256(byte a, int n) {
    byte res = 1;
    while (n != 0) {
        if (n % 2 == 1) { res = mulGF256Vieux(res, a);}
        a = mulGF256Vieux(a, a);
        n = n >> 1;
    };
    return res;
}



/********  Calcul de l'inverse de a, a^254, dans le corps à 256 éléments *****
           Ne sert plus.
*/


byte invGF256(byte a) {
    if (a == 0) return 0;
    return powGF256(a,254);
}



/****** Calcul de la somme modulo 2 des bits d'un octet ********
        Était utilisée dans l'ancienne version de SubByte.
        Ne sert plus.
*/


byte bitsum(byte a) {
    int res = 0;
    for (int i = 0; i < 8; i++) {
        res = res + (a % 2);
        a = a >> 1;
    }
    if ((res % 2) == 0) {return 0x00;} else {return 0x01;}
}


/****** Anciennes versions de SubByte et SubBytes
        Sont remplacées par une lecture dans le tableau SubByteTab. */


byte SubByteVieux(byte a) {
    
    byte m[8] = {
        0b11110001,
        0b11100011,
        0b11000111,
        0b10001111,
        0b00011111,
        0b00111110,
        0b01111100,
        0b11111000,
    };
    byte b = 0b01100011;
    
    byte res = 0;
    byte puiss2 = 1;
    
    a = invGF256(a);
    for (int i = 0; i < 8; i++) {
        res = res + puiss2 * (bitsum(m[i] & a));
        puiss2 = puiss2 << 1;
    }
    return res ^ b;
}


void SubBytesVieux(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = SubByteVieux(state[i%4][i/4]);
    }
}


/****** SubBytes
        Lecture dans le tableau SubByteTab. */


void SubBytes(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = SubByteTab[state[i%4][i/4]];
    }
}


/****** Anciennes versions de InvSubByte et InvSubBytes.
        Sont remplacées par une lecture dans le tableau InvSubByteTab. */


byte InvSubByteVieux(byte a) {
    byte i = 0;
    while ((SubByteVieux(i) != a) & (i <= 0xFF)) {
        i++;
    }
    return i;
}


void InvSubBytesVieux(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = InvSubByteVieux(state[i%4][i/4]);
    }
}


/****** Code mort: n'a jamais servi. */


byte InvSubByte(byte a) {
    return InvSubByteTab[a];
}


/****** InvSubBytes
        Lecture dans le tableau InvSubByteTab. */

 
void InvSubBytes(byte state[4][4]) {
    for (int i = 0; i < 4*4; i++) {
        state[i%4][i/4] = InvSubByteTab[state[i%4][i/4]];
    }
}


/****** Fabrication des tables SubByteTab et InvSubByteTab
        Les tables sont maintenant dans le source.
        Ne sert plus.
*/


void makeTable2() {
    FILE *flot;
    
    if ((flot = fopen("/Users/cyrillemoulin/Desktop/crypto/AES/AES/table2.c", "w")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture.");
    }
    for (int i = 0; i < 256; i++) {
        if ((i != 0) & (i % 10 == 0)) {fprintf(flot, "\n");};
        fprintf(flot, "0x%02x, ", InvSubByteVieux(i));
    }
    fclose(flot);
}


/****** Fabrication de la table de multiplication du corps à 256 éléments.
        Le résultat se trouve dans la table mulGF256Tab.
        Ne sert plus.
*/


void makemulGF256Tab() {
    FILE *flot;
    
    if ((flot = fopen("/Users/cyrillemoulin/Desktop/crypto/AES/AES/table3.c", "w")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture.");
    }
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
            if (j % 16 == 0) {fprintf(flot, "\n");};
            fprintf(flot, "0x%02x, ", mulGF256Vieux(i, j));
        }
        printf("\n");
    }
    fclose(flot);
}


/*****  Débogage:
        Affiche les 8 bits d'un octet.
 */

void showbits(byte a) {
    for (int i = 0; i < 8; i++) {
        if ((a & 128) == 128) {printf("1");} else {printf("0");};
        a = a << 1;
    }
    printf("\n");

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

/****** Débogage
        Affiche les 4*4 octets d'un "état".
*/


void ShowState(byte state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x  ", state[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}


/****** Applique ShiftRows à l'état sIn et écrit le résultat dans sOut.
 */

void ShiftRows(byte sIn[4][4], byte sOut[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = sIn[i][(i+j) % 4];
        }
    }
}


/****** Applique InvShiftRows à l'état sIn et écrit le résultat dans sOut.
 */

void InvShiftRows(byte sIn[4][4], byte sOut[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            sOut[i][j] = sIn[i][(-i+4+j) % 4];
        }
    }
}


/****** Test de Shiftrows.
        Ne sert plus.
 */
void TestShiftRows(byte state[4][4]) {
    ShowState(state);
    InvShiftRows(state, stateOut);
    ShowState(stateOut);
}


/**************** MixColumns and InvMixColumns ******************************/

/****** Matrice identité 4*4. A servi au débogage.
 */

byte identity[4][4] = {
    1, 0, 0, 0,
    0, 1, 0, 0,
    0, 0, 1, 0,
    0, 0, 0, 1 };


/****** Applique MixColumns à l'état sIn et écrit le résultat dans sOut.
 */

void MixColumns(byte sIn[4][4], byte sOut[4][4]) {
    
    byte m[4][4] = {
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


/****** Applique InvMixColumns à l'état sIn et écrit le résultat dans sOut.
 */
void InvMixColumns(byte sIn[4][4], byte sOut[4][4]) {
    
    byte m[4][4] = {
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


/****** Test de MixColumns.
        Ne sert plus.
 */

void TestMixColumns() {
    ShowState(identity);
    MixColumns(identity, stateOut);
    ShowState(stateOut);
    CopyAtoB(stateOut, stateIn);
    InvMixColumns(stateIn, stateOut);
    ShowState(stateOut);
}



/***************** KeyExpansion *****************************/

byte Rc[10];        // table construite par initRc
byte Rcon[4*10];    // table construite par initRcon



/****** Clé étendue utilisée pour crypter et décrypter. 
        Est construite par keyExpansion(). */

byte W[4*Nb*(Nr+1)];


/****** Débogage
        Affiche les 4 octets d'un mot en hexadécimal */

void ShowWord(byte *w) {
    for (int i = 0; i < 4; i++) {
        printf("%02x", w[i]);
    }
    printf(" ");
}


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


/****** Tests de InitRc et InitRcon. */

void TestInitRc() {
    InitRc();
    for (int i = 0; i < 10; i++) {
        printf("%02x  ", Rc[i]);
    }
    printf("\n");
}
 
void TestInitRcon() {
    InitRcon();
    for (int i = 0; i < 4*10; i += 4) {
        ShowWord(&Rcon[i]);
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


/****** Débogage
        Affiche le tableau W contenant la clé après extension.
        Ne sert plus. */

void ShowW() {
    for (int i = 0; i < 4*Nb*(Nr+1); i = i+4) {
        if (i % 4 == 0) {
            printf("\n");
        }
        ShowWord(&W[i]);
    }
}


/****** Test de KeyExpansion(). */

void TestKeyExpansion(byte k[]) {
    KeyExpansion(k);
    ShowW();
}



/***************** Chiffrement et Déchiffrement d'un état ********************/


/****** Applique AddRoundKey à sIn, le résultatt se trouve dans sIn. */

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


/****** Test de Cipher et Decipher. */

void TestCipher(byte sIn[4][4], byte sOut[4][4], byte k[4*Nk]) {
    
    printf("Cipher \n");
    ShowState(sIn);
    
    KeyExpansion(k);
   
    Cipher(sIn, sOut);
    printf("out : \n");
    ShowState(sOut);
    
    printf("Decipher \n");
    Decipher(sOut, sIn);
    ShowState(sIn);
}


/****** Chiffrement et Déchiffrement d'un fichier, version 1.
        Ne sert plus. */

int codageAES(char *fnameIn, char *fnameOut, byte k[4*Nk]) {
    FILE *in, *out;
    int c;
    byte sIn[4][Nb], sOut[4][Nb];
    
    KeyExpansion(k);
    
    if ((in = fopen(fnameIn, "r")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    if ((out = fopen(fnameOut, "w")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    
    while ((c = fgetc(in)) != EOF) {
        sIn[0][0] = c;
        for (int i = 1; i < 16; i++) {
            sIn[i%4][i/4] = fgetc(in);
        }
        Cipher(sIn, sOut);
        for (int i = 0; i < 16; i++) {
            fputc(sOut[i%4][i/4], out);
        }

    }
    fclose(in);
    fclose(out);
    return 0;
}


int decodageAES(char *fnameIn, char *fnameOut) {
    FILE *in, *out;
    int c;
    byte sIn[4][Nb], sOut[4][Nb];
    
    //KeyExpansion(key);
    
    if ((in = fopen(fnameIn, "r")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    if ((out = fopen(fnameOut, "w")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    
    while ((c = fgetc(in)) != EOF) {
        sIn[0][0] = c;
        for (int i = 1; i < 16; i++) {
            sIn[i%4][i/4] = fgetc(in);
        }
        //ShowState(sIn);
        Decipher(sIn, sOut);
        //ShowState(sOut);
        for (int i = 0; i < 16; i++) {
            fputc(sOut[i%4][i/4], out);
        }
        
    }
    fclose(in);
    fclose(out);
    return 0;
}


/* Test des 2 fonctions ci-dessus. */

#define ALICE "/Users/cyrillemoulin/Desktop/crypto/AES/AES/Alice.txt"
#define ALICEOUT "/Users/cyrillemoulin/Desktop/crypto/AES/AES/Aliceout.txt"
#define ALICEOUTOUT "/Users/cyrillemoulin/Desktop/crypto/AES/AES/Aliceoutout.txt"

#define IN "/Users/cyrillemoulin/Desktop/crypto/AES/AES/in.txt"
#define OUT "/Users/cyrillemoulin/Desktop/crypto/AES/AES/out.txt"
#define OUTOUT "/Users/cyrillemoulin/Desktop/crypto/AES/AES/outout.txt"


void TestCodageDecodage() {

    clock_t t1, t2;
    
    printf("codage\n");
    t1 = clock();
    codageAES(ALICE, ALICEOUT, key128);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    //printf("%i", CLOCKS_PER_SEC);
    
    //codageAES(IN, OUT, key);
    
    printf("decodage\n");
    t1 = clock();
    //decodageAES(OUT, OUTOUT);
    decodageAES(ALICEOUT, ALICEOUTOUT);
    t2 = clock();
    printf("%f\n", (t2 - t1)/(float)CLOCKS_PER_SEC);

}


/****** Chiffrement et Déchiffrement d'un fichier, version 2. */


#define MAX_SIZE_FILE  2048000

byte Alice[MAX_SIZE_FILE],
     AliceOut[MAX_SIZE_FILE],
     AliceOutOut[MAX_SIZE_FILE];

size_t tabSize;

/****** Le fichier à crypter est mis dans le tableau tab[] et 
        complété par des blancs pour que sa taille soit un multiple de 16.
        On peut aussi y mettre un fichier à décrypter. */

int FileInTab(char *fnameIn, byte tab[]) {
    FILE *in;
    
    if ((in = fopen(fnameIn, "r")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    int i = 0;
    char ch;
    while ((ch = fgetc(in)) != EOF) {
        tab[i++] = ch;
    }
    fclose(in);
    
    while (i%16 != 0) {
        tab[i++] = ' ';
    }
    
    tabSize = i;
    return 0;
}

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

/****** Ecrit le contenu du tableau de char t[] dans un fichier fnameOut. */

int TabInFile(byte tab[], char *fnameOut) {
    FILE *out;
    if ((out = fopen(fnameOut, "w")) == NULL) {
        fprintf(stderr, "Erreur d'ouverture de fichier.\n");
        return(EXIT_FAILURE);
    }
    for (int i = 0; i < tabSize; i++) {
        fputc(tab[i], out);
    }
    fclose(out);
    return 0;
}

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

/****** Chiffrement du tableau de tabIn[] avec la clé k[].
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


/****** test des 2 fonctions ci-dessus. */

void TestCodageDecodage2() {
    clock_t t1, t2;
    
    printf("FileInTab(ALICE)\n");
    t1 = clock();
    FileInTab(ALICE, Alice);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);

    printf("codageAES2\n");
    t1 = clock();
    codageAES2(Alice, key128, AliceOut);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    
    printf("TabInFile(ALICEOUT)\n");
    t1 = clock();
    TabInFile(AliceOut, ALICEOUT);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    
    printf("decodageAES2\n");
    t1 = clock();
    decodageAES2(AliceOut, key128, AliceOutOut);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    
    printf("TabInFile(ALICEOUTOUT)\n");
    t1 = clock();
    TabInFile(AliceOutOut, "AliceOutOutTest2");
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
}

/****** Test de decodageAES2(). */

void TestDecodageAES2() {
    clock_t t1, t2;

    printf("FileInTab(ALICEOUT)\n");
    t1 = clock();
    FileInTabVersion2(ALICEOUT, Alice);
    printf("%lu \n", tabSize);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    
    printf("decodageAES2\n");
    t1 = clock();
    decodageAES2(Alice, key128, AliceOut);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
    
    printf("TabInFile(ALICEOUTOUT)\n");
    t1 = clock();
    TabInFileVersion2(AliceOut, ALICEOUTOUT);
    t2 = clock();
    printf("%f \n", (t2 - t1)/ (float)CLOCKS_PER_SEC);
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
    //makemulGF256Tab();
    //TestShiftRows(identity);
    //TestMixColumns();
    //TestKeyExpansion(key256);
    //codage();
    //TestInitRcon();
    //TestCipher(inputEx2, stateOut, keyEx2);
    //TestCodageDecodage2();
    //TestDecodageAES2();

    /*
    for (int i = 0; i < argc; i++) {
       printf("argument n° %i : %s\n", i, argv[i]);
    }
     */
    
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
    } else {
        message();
    }
    
    return EXIT_SUCCESS;
}
