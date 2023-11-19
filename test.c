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

int main()
{
	const char *test = "Claudia0";
	char md5[33]; // 32 characters + null terminator
	bytes2md5(test, strlen(test), md5);
	printf("%s ======================> %s\n", test, md5);

        const char *test1 = "AAASAbabdeh.";

        bytes2md5(test1, strlen(test1), md5);
        printf("%s ======================> %s\n", test1, md5);




	return 0;
}
