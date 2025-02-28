#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/aes.h>
#include<openssl/evp.h>
#include<openssl/rand.h>

//AES keys for Encryption and Decryption

const unsigned char aes_key[] ="123456789abcdef";

void encrypt_decrypt_file(const char*, const char*);
void encrypt_aes(const unsigned char*, int , unsigned char*,unsigned char*, unsigned char*,int*);
void decrypt_aes(const unsigned char*, int , unsigned char*,unsigned char*, unsigned char*,int*);

int main()
{
	char choice;
   	char user_input[1024]; //buffer to store user input
	FILE *file;

	printf("You want to encrypt file then choose 'E' and For Decrypt file 'D'\n");
	scanf("%c",&choice);
	//get user input 
	if ((choice =='E')||(choice =='e'))
	{
	printf("Enter the text to save in myfile : \n");
	system("vim myfile_encrypt.txt");
//	fgets(user_input, sizeof(user_input), stdin);

	// save user input to myfile
	file = fopen("myfile_encrypt.txt","r");
	if(file ==NULL)
	{
		perror("Error opening file");
		return 1;

	}
	fputs(user_input, file);
	fclose(file);

	printf("Text save in myfile.txt\n");
	

	//encryption file
	encrypt_decrypt_file("myfile_encrypt.txt","encrypt");
	printf("File encrypted successfully\n");
	}
	else if (choice == 'D' || choice == 'd') {
        // Decrypt the file first
        encrypt_decrypt_file("myfile_encrypt.txt", "decrypt");

        // Open Vim for editing decrypted text
        printf("Opening myfile_decrypt.txt in Vim. Edit and save the file.\n");
        system("vim myfile_decrypt.txt");

        // Re-encrypt after editing
        encrypt_decrypt_file("myfile_decrypt.txt", "encrypt");
        printf("File decrypted, edited, and re-encrypted successfully!\n");
	}
	return 0;
}

// funtion to encrypt or decrypt a file 
 
void encrypt_decrypt_file(const char* path,const char* option)
{
	FILE *file;

	
	//open file
	if((file= fopen(path,"rb"))==NULL)
	{
		printf("Cannot open file %s\n",path);
		exit(EXIT_FAILURE);
	}

	//get file size
	fseek(file ,0, SEEK_END);
	size_t length_data = ftell(file);
	rewind(file);

	//read file contents
	unsigned char *aes_input= (unsigned char*)malloc(length_data);
	fread(aes_input,1,length_data,file);
	fclose(file);

	unsigned char iv[16];//initialization vector 
	if(!strcmp(option,"encrypt"))
	{
		RAND_bytes(iv,16); // Generate a random IV
		
		// Allocation memory for encrypt output
		unsigned char *enc_out = (unsigned char*)malloc(length_data+16);
		int enc_length = 0;

		//perform encryption
		encrypt_aes(aes_input, length_data,(unsigned char*)aes_key,iv,enc_out,&enc_length);

		// write IV + encrypted data to file
		file= fopen(path,"wb");
		fwrite(iv,1,16,file);
		fwrite(enc_out,1,enc_length,file);
		fclose(file);

		free(enc_out);
	}

	else if(!strcmp(option,"decrypt"))
	{//read IV form file
		memcpy(iv ,aes_input,16);

		unsigned char *dec_out = (unsigned char*)malloc(length_data - 16);
		int dec_length = 0;

		//perfrom decryption
		decrypt_aes(aes_input +16, length_data -16,(unsigned char*)aes_key,iv ,dec_out,&dec_length);

		//write decrypt data to file
		file = fopen(path,"wb");
		fwrite (dec_out,1, dec_length,file);
		fclose(file);

		free(dec_out);
		printf("Decrypted file successfully %s\n",path);

	}

	free(aes_input);

}
//AES encryption function
void encrypt_aes(const unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv,unsigned char *ciphertext, int *ciphertext_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;

	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(),NULL,key,iv);
	EVP_EncryptUpdate(ctx, ciphertext,ciphertext_len,plaintext,plaintext_len);
	EVP_EncryptFinal_ex(ctx,ciphertext + *ciphertext_len,&len);
	*ciphertext_len +=len;

	EVP_CIPHER_CTX_free(ctx);
}

//AES decryption function
void decrypt_aes(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv,unsigned char *plaintext, int *plaintext_len)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len;

	EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(),NULL,key,iv);
	EVP_DecryptUpdate(ctx, plaintext, plaintext_len,ciphertext, ciphertext_len);
	EVP_DecryptFinal_ex(ctx,plaintext + *plaintext_len,&len);
	*plaintext_len +=len;

	EVP_CIPHER_CTX_free(ctx);
}




/*
//Charactwer alphabet table of  base64

const unsigned char character_alphabet[] = "ABCDEFGHIJKLAMNOPQRSTUVWabcdefghijklmnopqrstuvwxyz0123456789+/";

//all functions used

void encrypt_decrypt_file(const char*, const char*);
unsigned char* encode(unsigned const char*);
unsigned char* decode(unsigned const char*);

//principal funtion 

int main(int argc , char  **argv)

{
	if (argc ==3)
	{
		if (!strcmp(argv[1], "encrypt"))
		{
			encrypt_decrypt_file(argv[2],"encrypt");

		}
		else if(!strcmp(argv[1],"decrypt"))
		{
			encrypt_decrypt_file(argv[2],"decrypt");
		}
		else
		{
			printf("Invalid option\n");
		}
	}
	else
	{
		printf("Invalid option\n");
	}
	return 0;
}

void encrypt_decrypt_file(const char* path,const char* option)
{
	//open file
	FILE *file;
	if ((file = fopen(path ,"r"))== NULL)
	{
		printf("cannot opne this file : %s\n",path);
		exit(0);
	}
	// get length of content in file 
	fseek(file ,0,SEEK_END);
	size_t length_data = ftell(file);
	rewind (file);

	//input data
	
	unsigned char*  aes_input = (unsigned char*)malloc(sizeof(unsigned char)* length_data + 1);
	//store content of in file in aes_input
	
	int  i=0;
	while(i< length_data)
	{
		*(aes_input+i) = getc(file);
		++i;
	}
	rewind(file);
	i =0;
	*(aes_input + length_data) = '\0';

	if(!strcmp(option, "encrypt"))
	{
		//AES-128 ,AES- 192,AES-256 bit
	AES_KEY enc_key;
		
	AES_set_encrypt_key(aes_key,128,&enc_key);

		//init vector
		unsigned char iv[AES_BLOCK_SIZE]; //iv always have to be sizeof(iv)  = 16
		memset(iv , 0x00, AES_BLOCK_SIZE);
		iv[AES_BLOCK_SIZE] = '\0';

		//buffer foer encryption

		size_t length_enc_out = ((length_data+ AES_BLOCK_SIZE)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
		if(!((length_data + AES_BLOCK_SIZE)%AES_BLOCK_SIZE))
			length_enc_out= length_data;

		unsigned char* enc_out = (unsigned char*)malloc(sizeof(unsigned char)*length_enc_out);

		//CBC encryption
		AES_cbc_encrypt(aes_input, enc_out,length_data,&enc_key, iv,AES_ENCRYPT);
		free(aes_input);

		//reropen file to clean it 

		fclose(file);
		file = fopen(path,"w");
		length_data=0;

		FILE *temporary_file = tmpfile();

		for(i=0;i<length_enc_out;i++)
		{
			fprintf(temporary_file, "0x%2x",*(enc_out+i));
			length_data +=5;

		}
		i=0;
		rewind(temporary_file);

		unsigned char *aes_input_base64 = (unsigned char* )malloc(sizeof(unsigned char)* (length_data+1));
		while(i<length_data)
		{
			*(aes_input_base64+i) = getc(temporary_file);
			++i;
		}
		*(aes_input_base64 + length_data) = '\0';
		fprintf(file ,"%s",encode(aes_input_base64));
		fclose(temporary_file);
		free(aes_input_base64);
		free(enc_out);
	}
	else if(!strcmp(option,"decrypt"))
	{
	//to change format the aes_input : base64 -->.hex-->.binary
		{
			FILE *temporary_file= tmpfile();
			fprintf(temporary_file,"%s",decode(aes_input));
			rewind(temporary_file);
			//clear aes_inpurt to store in it binary context

			memset(aes_input,0x00,length_data);
			length_data =0;
			//aes_input content a binary context

			while(1)
			{
				int in;
				if(feof(temporary_file))
					break;
				
				fscanf(temporary_file,"%x",&in);
				*(aes_input+length_data) = (char)in;
				length_data++;
			}
			fclose(temporary_file);
			aes_input = (unsigned char*)realloc(aes_input,sizeof(unsigned char)*length_data+1);
			*(aes_input+ length_data) = '\0';
		}

		AES_KEY dec_key;
		AES_set_decrypt_key(aes_key,128,&dec_key);

		unsigned char iv[AES_BLOCK_SIZE+1];
		memset(iv, 0x00, AES_BLOCK_SIZE);
		iv[AES_BLOCK_SIZE]= '\0';

		//
		//buffer for decryption
		 

		unsigned char *dec_out = (unsigned char*)malloc(sizeof(unsigned char)*length_data+1);

	//CBC decryption
	        AES_cbc_encrypt(aes_input, dec_out,length_data,&dec_key,iv ,AES_DECRYPT);
		free(aes_input);

		fclose(file);
		file = fopen(path , "w");

		fprintf(file,"%s",dec_out);
		free(dec_out);

	
	}
	else 
	{
		printf("Bad option\n");
	}
	fclose(file);

}

unsigned char* encode(unsigned  const char* string )
{
	// get string length
	int length_of_string = 0;
	while(string[length_of_string]!= '\0')
		length_of_string++;

	int number_of_binary = length_of_string*8;//multuiplication by 8 because each one character represents by 8 bit 
						  //padding to complete the 6  bits when using base table 64
	
	int padding =0;

	while (1)
	{
		if(number_of_binary %6 ==0)
			break;
		padding++;
		number_of_binary++;
	}

	 

	


	unsigned char* encode_data = (unsigned char*)malloc(sizeof(unsigned char)*((number_of_binary /6)+(padding+2)));
//pointer to store all  bit and calloc just to initialize frame with 0



	int *store_result_binary = (int *)calloc(sizeof(int),number_of_binary);

//jumpint(8 bit) during wheen bits store in pointer 
	 int z_index = 8;
	
	 for(int i=0;i<length_of_string;i++)
	 {
		 int index = z_index;
		 int quotien = string[i];
		 while(1)
		 {
			 if(quotien/2)
			 {
				 *(store_result_binary+(--index)) = quotien %2;
				 quotien /= 2;

			 }
			 else
			 {
				 *(store_result_binary+ (--index)) = quotien %2;
				 break;
			 }
			
		 }
		 index = z_index +=8;
	 }

	 int index = number_of_binary/6;
	 for(int i=(number_of_binary-1);i>0;i-=6)
	 {
		 int j=0;
		 int power =0;
		 double _6bit =0;

		 while(j<6)
		 {
			 if(*(store_result_binary + (i-j)) ==1)
			 {
				 int powe =1;
				 for(int k=0;k<power ;k++)
				 {
					 powe *=2;
				 }
				 _6bit = powe;
			 }
			 power++;
			 j++;

		 }
		 *(encode_data+(--index)) = *(character_alphabet +(int)_6bit);
	 }
	 // adding = just for padding
	if (padding==2)
		*(encode_data + (number_of_binary /6)) = '=';

	if(padding ==4)
	{
		*(encode_data + (number_of_binary /6)) = '=';
		*(encode_data + (number_of_binary /6)+1) = '=';
	}
	
		*(encode_data + ((number_of_binary /6)+ ( padding /2))) = '\0';

		free(store_result_binary);
		store_result_binary = NULL;
		
		return encode_data;

}


unsigned char* decode(unsigned const char* string)
{
	int length_of_string =0;
	while(string[length_of_string]!= '\0')
	length_of_string++;

	int padding=0;
	int i=0;

	while(i<length_of_string)
	{ 
		if (string[i]== '=')
		{
			++padding;
			
		}
		i++;
	
	}
	 int number_of_binary = ((length_of_string -padding)*6) - (padding*2);
	 unsigned char* decode_data = (unsigned char*)malloc(sizeof(unsigned char)*(number_of_binary/8)+1);
	 int *store_result_binary = (int*)calloc(sizeof(int),number_of_binary*8);
	 
	 int z_index =6;

	 for(i=0;i<(length_of_string- padding);i++)
	{
		int index =  z_index;
		int quotien =0;
		for(int j=0;j<64;j++)
		{
			if(string[i] ==character_alphabet[j])
			{
				quotien = j;
					break;
			}
		}
		while(1)
		{
			if(quotien/2)
			{
				*(store_result_binary +(--index)) = quotien %2;
			}
			else 
			{
				*(store_result_binary+(--index)) = quotien %2;
				break;
			}
		}
		index = z_index +=6;

	}

	 int index =0;
	 for(i=0;i<number_of_binary;i+=8)
	 {
		 int j=7;
		 int power =0;
		 double _8bit =0;
		 while(j>=0)
		 {
			if(*(store_result_binary +(i+j))==1)

			{
				int powe =1;
				for(int k=0;k<power;k++)
				{
					powe *=2;
				}
				_8bit *= powe;
			}
			power++;
			j--;
		 
		 }
		 *(decode_data+(index++)) = (int)_8bit;
		 j=7;
		 power =0;
		 _8bit =0;

	 }
	 *(decode_data + (number_of_binary/8)+1) = '\0';
	 free(store_result_binary);
	 store_result_binary = NULL;

	 return decode_data;

}*/




