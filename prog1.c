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



int NUM_THREADS;

struct timespec start_time;

typedef struct {
   int repetitions;
   int type;
   int thread_number;
} thread_data;

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
long task_number;

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



void *prod(void *arg)
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
	thread_data* data = (thread_data*)arg;
	int repetitions = data->repetitions;
    int type = data->type;
	int thread_number = data->thread_number;

	while (1)
	{
		for(int i=thread_number-1;i<password_counter;i=i+repetitions)
		{
			t1=passwords[i];
			// printf("Thread %s: %s\n", t1, t1);
			for(int j=0; j<words_counter;j++)
			{
				
				t2=dictionary[j];
				length=strlen(t2);
				char letters[100]; 
				char letters_number[100];
				char number_letter[100];
				char number_letter_number[100]; 
				strcpy(letters, t2);

				if(type == 1){
					for(int z = 0; z < length; z++) {
						letters[z] = toupper((unsigned char) letters[z]);
					}
				} else if (type == 2 ){
					for(int z = 0; z < length; z++) {
						letters[z] = tolower((unsigned char) letters[z]);
					}
				} else if (type == 3 ){
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

				// printf("Thread %s: %s\n", number_letter, t2);

				if((strcmp(t1,md5_1))==0 && passwords[i][0]!='#')
				{
					pthread_mutex_lock(&lock);
					decodedpassword=malloc(strlen(letters)*sizeof(char));
					strcpy(decodedpassword, letters);
					counter++;
					taskid=type;
					task_number=thread_number;
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
					taskid=type;
					task_number=thread_number;
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
					taskid=type;
					task_number=thread_number;
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
					taskid=type;
					task_number=thread_number;
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
		printf("\nOtrzymano sygnal przez konsumenta.\nHaslo znalezione: %s.\nPrzez producenta nr: %ld.%ld\n\n",decodedpassword,taskid,task_number);
		if(decodedpassword != NULL) {
            free(decodedpassword);
            decodedpassword=NULL;
        }
		struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);

            // Oblicz różnicę między obecnym czasem a czasem rozpoczęcia
        double elapsed_time = end_time.tv_sec - start_time.tv_sec;
        elapsed_time += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

		FILE *file = fopen("3_watkow_2_bior2.txt", "a");
            if (file != NULL) {
                // Zapisz hasło do pliku
                fprintf(file, "%.2f\n", elapsed_time);

                // Zamknij plik
                fclose(file);
			}
	}
	pthread_mutex_unlock(&lock);

        pthread_exit(NULL);
}




int main (int argc, char *argv[]){
	NUM_THREADS = sysconf(_SC_NPROCESSORS_ONLN)-8;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	long t1=1,t2=2,t3=3,t4=4,t5=5;
	int i,rc;
	int row=0, type_1_counter=0, type_2_counter=0, type_3_counter=0;
	pthread_attr_t attr;
	pthread_t threads[NUM_THREADS];
	size_t length;
	char tmp[33];
	long number_of_words=0, number_of_passwords=0;
	char *word=NULL;
	pthread_mutex_init(&lock, NULL);
	counter=0;
	int num_processors = sysconf(_SC_NPROCESSORS_ONLN);
	thread_data threadData[NUM_THREADS];
	for (int i = 0; i < NUM_THREADS-1; i++) {
		if (i%3 == 0) {
			threadData[i].type = 1;
			threadData[i].thread_number = i/3+1;

			threadData[i].repetitions = 0;
			type_1_counter++;
		} else if (i%3 == 1) {
			threadData[i].type = 2;
			threadData[i].thread_number = i/3+1;
			threadData[i].repetitions = 0;
			type_2_counter++;
		} else if (i%3 == 2) {
			threadData[i].type = 3;
			threadData[i].thread_number = i/3+1;
			threadData[i].repetitions = 0;
			type_3_counter++;
		}
	}

	for (int i = 0; i < NUM_THREADS-1; i++) {
		if (i%3 == 0) {
			threadData[i].repetitions = type_1_counter;
		} else if (i%3 == 1) {
			threadData[i].repetitions = type_2_counter;
		} else if (i%3 == 2) {
			threadData[i].repetitions = type_3_counter;
		}
	}
	FILE *fp1=fopen("md5_hasla.txt","r");
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
	pthread_mutex_init(&lock, NULL);
	pthread_cond_init (&condvar, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	for (int i = 0; i < NUM_THREADS; i++) {
		if (i == 0) {
			pthread_create(&threads[i], &attr, kon, (void *)t1);
		}
		else {
        	pthread_create(&threads[i], &attr, prod, &threadData[i-1]);
		}	

    }


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
