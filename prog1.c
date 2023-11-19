#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>


#define NUM_THREADS 5

char passwords[1000][33];
pthread_mutex_t lock;
long wynik=0;
char **dictionary;
long words_counter;
long password_counter;
pthread_cond_t condvar;
char *decodedpassword = NULL;
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


void *prod1(void *t)
{
	char md5_1[33];
	char md5_2[33];
	char md5_3[33];
	char md5_4[33];
	char const *t1;
	char const *t2;
	int lower=0;
	int length=0;
	char digits[1000]; 
	int digit = 0;
	while (1)
	{

	
		for(int i=0;i<password_counter;i++)
		{

			t1=passwords[i];
			for(int j=0; j<words_counter;j++)
			{

				t2=dictionary[j];
				length=strlen(t2);
				char small_letters[100]; 
				char small_letters_number[100];
				char number_small_letter[100];
				char number_small_letter_number[100]; 
				strcpy(small_letters, t2);

				for(int z = 0; z < length; z++) {
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
					pthread_mutex_lock(&lock);
					decodedpassword = malloc(strlen(small_letters)*sizeof(char));
					strcpy(decodedpassword, small_letters);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					
					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(small_letters_number)*sizeof(char));
					strcpy(decodedpassword, small_letters_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_small_letter)*sizeof(char));
					strcpy(decodedpassword, number_small_letter);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_small_letter_number)*sizeof(char));
					strcpy(decodedpassword, number_small_letter_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				

			}
		}
		digit++;

	}
	pthread_exit(NULL);
}

void *prod2(void *t)
{
    char md5_1[33];
	char md5_2[33];
	char md5_3[33];
	char md5_4[33];
	char const *t1;
	char const *t2;
	int lower=0;
	int length=0;
	char digits[1000]; 
	int digit = 0;

	while (1)
	{

	
		for(int i=0;i<password_counter;i++)
		{

			t1=passwords[i];
			for(int j=0; j<words_counter;j++)
			{

				t2=dictionary[j];
				length=strlen(t2);
				char letters[100]; 
				char letters_number[100];
				char number_letter[100];
				char number_letter_number[100]; 
				strcpy(letters, t2);

				for(int z = 0; z < length; z++) {
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
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(letters)*sizeof(char));
					strcpy(decodedpassword, letters);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(letters_number)*sizeof(char));
					strcpy(decodedpassword, letters_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_letter)*sizeof(char));
					strcpy(decodedpassword, number_letter);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_letter_number)*sizeof(char));
					strcpy(decodedpassword, number_letter_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				

			}
		}
		digit++;

	}

        pthread_exit(NULL);

}
void *prod3(void *t)
{
    char md5_1[33];
	char md5_2[33];
	char md5_3[33];
	char md5_4[33];
	char const *t1;
	char const *t2;
	int lower=0;
	int length=0;
	char digits[1000]; 
	int digit = 0;

	while (1)
	{
	
		for(int i=0;i<password_counter;i++)
		{

			t1=passwords[i];
			for(int j=0; j<words_counter;j++)
			{

				t2=dictionary[j];
				length=strlen(t2);
				char upper_letters[100]; 
				char upper_letters_number[100];
				char number_upper_letter[100];
				char number_upper_letter_number[100]; 
				strcpy(upper_letters, t2);

				for(int z = 0; z < length; z++) {
					upper_letters[z] = toupper((unsigned char) upper_letters[z]);
				}
				sprintf(digits, "%d", digit);

				strcpy(upper_letters_number, upper_letters);
				strcpy(number_upper_letter, digits);


				strcat(upper_letters_number, digits);
				strcat(number_upper_letter, upper_letters);

				strcpy(number_upper_letter_number, number_upper_letter);
				strcat(number_upper_letter_number, digits);

				bytes2md5(upper_letters,strlen(upper_letters),md5_1);
				bytes2md5(upper_letters_number,strlen(upper_letters_number),md5_2);
				bytes2md5(number_upper_letter,strlen(number_upper_letter),md5_3);
				bytes2md5(number_upper_letter_number,strlen(number_upper_letter_number),md5_4);


				if((strcmp(t1,md5_1))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword = malloc(strlen(upper_letters)*sizeof(char));
					strcpy(decodedpassword, upper_letters);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_2))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(upper_letters_number)*sizeof(char));
					strcpy(decodedpassword, upper_letters_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_3))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_upper_letter)*sizeof(char));
					strcpy(decodedpassword, number_upper_letter);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				else if ((strcmp(t1,md5_4))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(number_upper_letter_number)*sizeof(char));
					strcpy(decodedpassword, number_upper_letter_number);
					counter++;
					taskid=(long)t;
					passwords[i][0]='#';
					pthread_cond_signal(&condvar);
					pthread_mutex_unlock(&lock);
					break;
				}
				

			}
		}
		digit++;

	}

        pthread_exit(NULL);
}



void *kon(void *t)
{

	pthread_mutex_lock(&lock);
	signal(SIGHUP,sighup_handle);
	while(1)
	{
		pthread_cond_wait(&condvar, &lock);
		printf("\nOtrzymano sygnal przez konsumenta.\nHaslo znalezione: %s.\nPrzez producenta nr:%ld\n\n",decodedpassword,taskid);
		if(decodedpassword != NULL) {
            free(decodedpassword);
            decodedpassword=NULL;
        }
	}
	pthread_mutex_unlock(&lock);

        pthread_exit(NULL);
}




int main (int argc, char *argv[]){

	long t1=1,t2=2,t3=3,t4=4,t5=5;
	int i,rc;
	int row=0;
	pthread_attr_t attr;
	pthread_t threads[NUM_THREADS];
	size_t length;
	char tmp[33];
	long number_of_words=0, number_of_passwords=0;
	char *word=NULL;
	pthread_mutex_init(&lock, NULL);
	counter=0;

	FILE *fp1=fopen("passwords.txt","r");
	while(fscanf(fp1,"%s",passwords[row])!=EOF)
	{
		passwords[row][32]='\0';
		row++;
		number_of_passwords++;
	}
	fclose(fp1);
	password_counter=number_of_passwords;
	FILE *fp2=fopen("dictionary.txt","r");
	dictionary=(char**)malloc(sizeof(char*));
	while(fscanf(fp2,"%s",tmp)!=EOF)
	{
		length=strlen(tmp);
		word=(char*)malloc(length+1);
		for(int i=0;i<length;i++)
		{
			word[i]=tmp[i];
//			printf("%s\n",word);
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
//			printf("%ld\n",number_of_words);
//			printf("%s\n",word);

		}
	}
	fclose(fp2);
	words_counter=number_of_words;
	pthread_mutex_init(&lock, NULL);
	pthread_cond_init (&condvar, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_create(&threads[0], &attr, prod1, (void *)t1);
 	pthread_create(&threads[1], &attr, prod2, (void *)t2);
  	pthread_create(&threads[2], &attr, prod3, (void *)t3);
	pthread_create(&threads[3], &attr, kon, (void *)t5);


	for (i = 0; i < NUM_THREADS; i++) {
    		pthread_join(threads[i], NULL);
	}

	for(int i=0;i<words_counter;i++)
	{
		free(dictionary[i]);
	}
	free(dictionary);

	free(word);

	pthread_attr_destroy(&attr);
	pthread_mutex_destroy(&lock);
	pthread_cond_destroy(&condvar);
	pthread_exit(NULL);
}
