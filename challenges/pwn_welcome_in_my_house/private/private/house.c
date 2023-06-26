#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void create_user() {
	printf("Enter username: ");
	char *data = (char*)malloc(25);
	scanf("%s", data);
	printf("\n");
	char *buf1 = (char*)malloc(24);
	strcpy(buf1, data);

	printf("Enter password: ");
	char *ch = (char*)malloc(24);
	scanf("%s", ch);
	printf("\n");
	
	printf("Enter disk space: "); 
	printf("\n");
	u_int64_t m;
	scanf("%lu", &m);
	malloc(m);

	strcpy(malloc(24), ch);


}

void read_flag(char *admin) {
	if (strcmp(admin, "root") == 0) {
		system("cat flag.txt");
	} else {
		printf("[-] You have to be root to read flag!\n\n");
	}
}

int menu(char *admin) {
	while(1) {
		int choice;
		printf("[!]	Welcome in my house!	[!]\n\n");

		printf("Actual user: %s\n\n", admin);

		printf( "1. Create user\n"\
			"2. Read flag\n"\
			"3. Exit\n\n");

		printf(">>  ");
		scanf("%d", &choice);
		printf("\n");
		if(choice == 1) {
			create_user();
		} else if(choice== 2) {
			read_flag(admin);
		} else if(choice == 3) {
			exit(EXIT_SUCCESS);
		}
	}
}
int main() {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	char *admin = (char*)malloc(24);
	strcpy(admin, "admin");

	menu(admin);
	return 0;
}
