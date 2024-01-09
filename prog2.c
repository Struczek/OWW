#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>


#define NUM_THREADS 5

struct timespec start_time;

char passwords[1000][33];
long wynik=0;
char **dictionary;
long words_counter;
const char *decodedpassword;
int counter;
long taskid;

void bytes2md5(const char *data, int len, char *md5buf) {
	  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	  const EVP_MD *md = EVP_md5();
	  unsigned char md_value[EVP_MAX_MD_SIZE];
	  unsigned int md_len, i;
	  EVP_DigestInit_ex(mdctx, md, NULL);
	  EVP_DigestUpdate(mdctx, data, len);
	  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	  EVP_MD_CTX_free(mdctx);
	  for (i = 0; i < md_len; i++) {
		snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
	  }
}


void sighup_handle(int sig)
{
        printf("Ilosc zlamanych hasel: %d\n",counter);
}



int main (int argc, char *argv[]){
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	int i,rc;
	int row=0;
	size_t length;
	char tmp[33];
	long number_of_words=0, number_of_passwords=0;
	char *word=NULL;
	counter=0;

	FILE *fp1=fopen("md5_hasla.txt","r");
	while(fscanf(fp1,"%s",passwords[row])!=EOF)
	{
		passwords[row][32]='\0';
		row++;
        number_of_passwords++;
	}
	fclose(fp1);

	FILE *fp2=fopen("dictionary.txt","r");
	dictionary=(char**)malloc(sizeof(char*));
	while(fscanf(fp2,"%s",tmp)!=EOF)
	{
		length=strlen(tmp);
		word=(char*)malloc(length+1);
		for(int i=0;i<length;i++)
		{
			word[i]=tmp[i];
            // printf("%d\n",word[0]);
		}
		word[length]='\0';
		number_of_words++;
		if(number_of_words==1)
		{
			dictionary[0]=word;
		}
		if(number_of_words>1)
		{
			dictionary=(char **)realloc(dictionary,number_of_words*sizeof(char *));
			dictionary[number_of_words-1]=word;
		}
	}
	fclose(fp2);


	words_counter=number_of_words;

    char md5_1[33];
	char md5_2[33];
	char md5_3[33];
	char md5_4[33];
	char const *t1;
	char const *t2;
	int lower=0;
	int length1=0;
	char digits[1000]; 
	int digit = 0;
	while (1)
	{

		signal(SIGHUP,sighup_handle);
		for(int i=0;i<number_of_passwords;i++)
		{

			t1=passwords[i];
			for(int j=0; j<words_counter;j++)
			{
				t2=dictionary[j];
				length1=strlen(t2);
				char small_letters[100]; 
				char small_letters_number[100];
				char number_small_letter[100];
				char number_small_letter_number[100]; 
				strcpy(small_letters, t2);

				for(int z = 0; z < length1; z++) {
					small_letters[z] = tolower((unsigned char) small_letters[z]);
				}
				sprintf(digits, "%d", digit);

				strcpy(small_letters_number, small_letters);
				strcpy(number_small_letter, digits);


				strcat(small_letters_number, digits);
				strcat(number_small_letter, small_letters);

				strcpy(number_small_letter_number, number_small_letter);
				strcat(number_small_letter_number, digits);


				bytes2md5(small_letters,strlen(small_letters),md5_1);
				bytes2md5(small_letters_number,strlen(small_letters_number),md5_2);
				bytes2md5(number_small_letter,strlen(number_small_letter),md5_3);
				bytes2md5(number_small_letter_number,strlen(number_small_letter_number),md5_4);


				if((strcmp(t1,md5_1))==0 && passwords[i][0]!='#')
				{
					decodedpassword=small_letters;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
                    printf("Password %d: %s\n",counter,decodedpassword);

					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					decodedpassword=small_letters_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);

					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_small_letter;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_small_letter_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
                t2=dictionary[j];
				length1=strlen(t2);
				char letters[100]; 
				char letters_number[100];
				char number_letter[100];
				char number_letter_number[100]; // Adjust size as needed
				strcpy(letters, t2);

				for(int z = 0; z < length1; z++) {
					if (z==0)
					{
						letters[z] = toupper((unsigned char) letters[z]);
					}
					else
					{
						letters[z] = tolower((unsigned char) letters[z]);
					}
				}
				sprintf(digits, "%d", digit);

				strcpy(letters_number, letters);
				strcpy(number_letter, digits);


				strcat(letters_number, digits);
				strcat(number_letter, letters);

				strcpy(number_letter_number, number_letter);
				strcat(number_letter_number, digits);

				bytes2md5(letters,strlen(letters),md5_1);
				bytes2md5(letters_number,strlen(letters_number),md5_2);
				bytes2md5(number_letter,strlen(number_letter),md5_3);
				bytes2md5(number_letter_number,strlen(number_letter_number),md5_4);


				if((strcmp(t1,md5_1))==0 && passwords[i][0]!='#')
				{
					decodedpassword=letters;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					decodedpassword=letters_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_letter;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_letter_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				
                t2=dictionary[j];
				length1=strlen(t2);
				char upper_letters[100]; 
				char upper_letters_number[100];
				char number_upper_letter[100];
				char number_upper_letter_number[100]; 
				strcpy(upper_letters, t2);

				for(int z = 0; z < length1; z++) {
					upper_letters[z] = toupper((unsigned char) upper_letters[z]);
				}
				sprintf(digits, "%d", digit);

				strcpy(upper_letters_number, upper_letters);
				strcpy(number_upper_letter, digits);


				strcat(upper_letters_number, digits);
				strcat(number_upper_letter, upper_letters);

				strcpy(number_upper_letter_number, number_upper_letter);
				strcat(number_upper_letter_number, digits);

				bytes2md5(upper_letters,strlen(t2),md5_1);
				bytes2md5(upper_letters_number,strlen(t2),md5_2);
				bytes2md5(number_upper_letter,strlen(t2),md5_3);
				bytes2md5(number_upper_letter_number,strlen(t2),md5_4);


				if((strcmp(t1,md5_1))==0 && passwords[i][0]!='#')
				{
					decodedpassword=upper_letters;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					decodedpassword=upper_letters_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_upper_letter;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					decodedpassword=number_upper_letter_number;
					counter++;
					passwords[i][0]='#';
					struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("pojedyncze_2_zbior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
					printf("Password %d: %s\n",counter,decodedpassword);
					break;
				}
				

			}
		}
		digit++;

	}
    
	

	for(int i=0;i<words_counter;i++)
	{
		free(dictionary[i]);
	}
	free(dictionary);

	free(word);

	return 0;
}
