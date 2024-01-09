#include  	<openssl/evp.h>
#include  	<string.h>



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

void process_passwords() {
    FILE *input_file = fopen("hasla_v2.txt", "r");
    FILE *output_file = fopen("md5_hasla.txt", "w");

    if (input_file != NULL && output_file != NULL) {
        char password[100];
        char md5[33];

        while (fgets(password, sizeof(password), input_file) != NULL) {
            // Remove the newline character from the password
            password[strcspn(password, "\n")] = 0;
			const char *test = password;

            bytes2md5(test, strlen(test), md5);
            fprintf(output_file,"%s\n",md5);
        }

        fclose(input_file);
        fclose(output_file);
    }
}


int main()
{
	FILE *input_file = fopen("hasla_v2.txt", "r");
    FILE *output_file = fopen("md5_hasla.txt", "w");

    if (input_file != NULL && output_file != NULL) {
        char password[100];
        char md5[33];

        while (fscanf(input_file, "%99s", password) == 1) {
            // Remove the newline character from the password
            password[strcspn(password, "\n")] = '\0';
			const char *test = password;

            bytes2md5(test, strlen(test), md5);
            fprintf(output_file,"%s\n",md5);
        }

        fclose(input_file);
        fclose(output_file);
    }
	const char *test = "vetoistical";
	char md5[33]; // 32 characters + null terminator
	// process_passwords();
	bytes2md5(test, strlen(test), md5);
	printf("%s ======================> %s\n", test, md5);

        const char *test1 = "AAASAbabdeh.";

        bytes2md5(test1, strlen(test1), md5);
        printf("%s ======================> %s\n", test1, md5);




	return 0;
}
