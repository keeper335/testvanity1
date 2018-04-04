/* vanitygen.c - Super Vanitygen - Vanity Bitcoin address generator */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "externs.h"

/* Number of secp256k1 operations per batch */
#define STEP 3072
#define THREADS_NUM 1
#define ADDRESS_NUM 1
#define ERROR_CREATE_THREAD     -11

#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"



#define MY_VERSION "0.3"

const char fname_result[] = "found.txt";

const char *adr_to_find[] = {"1LzhS3k3e9Ub8i2W1V8xQFdB8n2MYCHPCa", "17aPYR1m6pVAacXg1PTDDU7XafvK1dxvhi", "15c9mPGLku1HuW9LRtBf4jcHVpBUt8txKz",
  "1Dn8NF8qDyyfHMktmuoQLGyjWmZXgvosXf", "1HAX2n9Uruu9YDt4cqRgYcvtGvZj1rbUyt", "1Kn5h2qpgw9mWE5jKpk8PP4qvvJ1QVy8su", "1AVJKwzs9AskraJLGHAZPiaZcrpDr1U6AB"};

/* Global command-line settings */

/* Per-thread hash counter */
static uint64_t *thread_count;

typedef struct {
    uint64_t *thread_count;
    int thread_num;
    int sock;
}   thread_struct_t;

static uint8_t *pattern_to_find[ADDRESS_NUM];

/* Socket pair for sending up results */
static int sock[2];

void workWithGPU();
void cleanupGPU(cl_context context, cl_command_queue que, cl_program program, cl_kernel kernel, cl_mem *memObjects) ;
/* Static Functions */
static void manager_loop(int threads);
static void announce_result(int found, const uint8_t result[52]);
void *engine(void *args_);
static bool verify_key(const uint8_t result[52]);

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a);
static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b);

//sup

void scalartohex(unsigned char *buf, secp256k1_scalar *scalar) {
    uint32_t *p=(uint32_t *)scalar->d;
    sprintf(buf + strlen(buf), "%016lx%016lx%016lx%016lx", p[3],p[2],p[1],p[0]);
}
/*
secp256k1_scalar getRandomScalar8BytesVoid(void) {
    secp256k1_scalar scalar;
    uint64_t d = (uint64_t)(rand() & 0xFFFF) | (uint64_t)(rand() & 0xFFFF) << 16 | (uint64_t)(rand() & 0xFFFF) << 32 | (uint64_t)(rand() & 0xFFFF) << 48;
    memset(&scalar, 0, sizeof(scalar));
    memcpy(&scalar, &d, sizeof(d));
    return scalar;
}

secp256k1_scalar getRandomScalar8BytesU16(uint16_t setWord) {
    secp256k1_scalar scalar;
    uint16_t *s;
    uint64_t d = (uint64_t)(rand() & 0xFFFF) | (uint64_t)(rand() & 0xFFFF) << 16 | (uint64_t)(rand() & 0xFFFF) << 32 | (uint64_t)(rand() & 0xFFFF) << 48;
    memset(&scalar, 0, sizeof(scalar));
    memcpy(&scalar, &d, sizeof(d));
    s = (uint16_t *)scalar.d;
    s[3] = setWord;
    return scalar;
}
*/
void randScalar7Bytes(secp256k1_scalar *scalar, uint8_t setByte) {
    uint8_t *p = (uint8_t *)scalar->d;
    memset(scalar, 0, sizeof(secp256k1_scalar));
    p[4] = rand() & 0xFF;
    p[5] = rand() & 0xFF;
    p[6] = setByte;

    unsigned char buf[128];
    scalartohex(buf, scalar);
    printf("Scalar hex %s\n", buf);
}

// 5 bytes 3,5MH/s -> 314146 seconds -> 5235 mins -> 87 Hours -> 4 days
// 6 bytes -> 80421421 seconds -> 22339 hours -> 930 days


static bool add_prefix2(const char *prefix, uint8_t *pattern)
{
  /* Determine range of matching public keys */
  size_t pattern_sz=25;
  size_t b58sz=strlen(prefix);
  uint8_t pattern1[32];
  int j;

  if(!b58tobin(pattern1, &pattern_sz, prefix, b58sz)) {
    fprintf(stderr, "Error: Address '%s' contains an invalid character.\n",
            prefix);
    return 0;
  }

  printf("add prefix %s and its pattern ", prefix);
  for(j=1;j < 21;j++) printf("%02x", pattern1[j]);
  printf("\n");
  memcpy(pattern, pattern1+1, 20);
  
  return 1;
}


/**** Main Program ***********************************************************/

#define parse_arg()     \
  if(argv[i][j+1])      \
    arg=&argv[i][j+1];  \
  else if(i+1 < argc)   \
    arg=argv[++i];      \
  else                  \
    goto no_arg

// Main program entry.
//
int main(int argc, char *argv[])
{
  int threads = THREADS_NUM;
  int i, status;// ncpus=get_num_cpus(), threads=ncpus;
  pthread_t pthreads[threads];
  thread_struct_t *args;
  
  workWithGPU();
  return 1;

  args = (thread_struct_t *) malloc (sizeof(thread_struct_t) * threads);
  // Convert specified prefixes into a global list of public key byte patterns.
  
  for(i=0;i < ADDRESS_NUM; i++) {
    pattern_to_find[i] = (uint8_t*) malloc(sizeof(uint8_t) * 21);
    if(!add_prefix2(adr_to_find[i], pattern_to_find[i])) {
      goto error1;
    }
  }
  
  // Create memory-mapped area shared between all threads for reporting hash
  // counts.
  thread_count=mmap(NULL, threads*sizeof(uint64_t), PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_ANONYMOUS/*|MAP_LOCKED*/, -1, 0);
  if(thread_count == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  
  /* Create anonymous socket pair for children to send up solutions */
  if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sock)) {
    perror("socketpair");
    return 1;
  }

  /* Ignore signals */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  for(i=0;i < threads;i++) {
    args[i].thread_num = i;
    args[i].thread_count = thread_count;
    args[i].sock = sock[1];
    status = pthread_create(&pthreads[i], NULL, engine, (void *)&args[i]);
    if (status != 0) {
        printf("main error: can't create thread, status = %d\n", status);
        exit(ERROR_CREATE_THREAD);
    }
  }


  manager_loop(threads);
  
  printf("Exit\n");
  
    /* Close the write end of the socketpair */
  close(sock[1]);
  close(sock[0]);
  
error1:
    for(i=0; i< ADDRESS_NUM;i++)
        free(pattern_to_find[i]);
  free(args);
  return 1;
}

// Parent process loop, which tracks hash counts and announces new results to
// standard output.
//
static void manager_loop(int threads)
{

  fd_set readset;
  struct timeval tv={1, 0};
  char msg[256];
  uint8_t result[52];
  uint64_t prev=0, last_result=0, count, avg, count_avg[8];
  int i, ret, len, found=0, count_index=0, count_max=0;

  FD_ZERO(&readset);

  while(1) {
    /* Wait up to 1 second for hashes to be reported */
    FD_SET(sock[0], &readset);
    if((ret=select(sock[0]+1, &readset, NULL, NULL, &tv)) == -1) {
      perror("select");
      return;
    }

    if(ret) {
      /* Read the (PrivKey,PubKey) tuple from the socket */
      if((len=read(sock[0], result, 52)) != 52) {
        /* Datagram read wasn't 52 bytes; ignore message */
        if(len != -1)
          continue;

        /* Something went very wrong if this happens; exit */
        perror("read");
        return;
      }

      /* Verify we received a valid (PrivKey,PubKey) tuple */
      if(!verify_key(result))
        continue;

      announce_result(++found, result);

      /* Reset hash count */
      for(i=0,count=0;i < threads;i++)
        count += thread_count[i];
      last_result=count;
      continue;
    }

    /* Reset the select() timer */
    tv.tv_sec=1, tv.tv_usec=0;

    /* Collect updated hash counts */
    for(i=0,count=0;i < threads;i++)
      count += thread_count[i];
    count_avg[count_index]=count-prev;
    if(++count_index > count_max)
      count_max=count_index;
    if(count_index == NELEM(count_avg))
      count_index=0;
    prev=count;
    count -= last_result;

    /* Average the last 8 seconds */
    for(i=0,avg=0;i < count_max;i++)
      avg += count_avg[i];
    avg /= count_max;

    sprintf(msg, "[%llu Kkey/s][Total %llu]", (avg+500)/1000, count);

    /* Display match count */
    if(found) {
        sprintf(msg+strlen(msg), "[Found %d]", found);
    }

    printf("\r%-78.78s", msg);
    fflush(stdout);
  }
}

static void announce_result(int found, const uint8_t result[52])
{
  uint8_t pub_block[RIPEMD160_DIGEST_LENGTH + 5] = {0,},checksum[SHA256_DIGEST_LENGTH], wif[35];
  int j;
  char buf[512];
  FILE *fp;
  
  memset(buf, 0, 256);

  printf("\n");

  /* Display matching keys in hexadecimal */
  sprintf(buf + strlen(buf),"Private match: ");
  for(j=0;j < 32;j++)
      sprintf(buf + strlen(buf), "%02x", result[j]);
  sprintf(buf + strlen(buf), "\nPublic match:  ");
  for(j=0;j < 20;j++)
      sprintf(buf + strlen(buf), "%02x", result[j+32]);

  /* Convert Public Key to Compressed WIF */
  memcpy(pub_block+1, result+32, 20);
  /* Compute checksum and copy first 4-bytes to end of public key */
  SHA256(pub_block, RIPEMD160_DIGEST_LENGTH + 1, checksum);
  SHA256(checksum, SHA256_DIGEST_LENGTH, checksum);
  memcpy(pub_block+21, checksum, 4);
  b58enc(wif, pub_block, sizeof(pub_block));

  sprintf(buf + strlen(buf), "\nAddress:       %s\n---\n", wif);
  printf("%s", buf);

  if ((fp=fopen(fname_result, "a+"))==NULL) {
    printf("Cannot open file %s\n", fname_result);
    exit (1);
  }
  fprintf(fp, "%s", buf);
  fclose(fp);
}


/**** Hash Engine ************************************************************/

// Per-thread entry point.
//
void *engine(void *args_)
{
    thread_struct_t *args = (thread_struct_t *)args_;
  static secp256k1_gej base[STEP];
  static secp256k1_ge rslt[STEP];
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar_key, scalar_one={{1}}, scalar_step;
  secp256k1_gej temp;
  secp256k1_ge offset;
  int thread = args->thread_num;

  uint8_t sha_block[SHA256_DIGEST_LENGTH+1], rmd_block[SHA256_DIGEST_LENGTH], result[52], *pubkey=result+32;
  uint64_t *key=(uint64_t *)result;
  int i, k;//, fd, len;
  int j;

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_scalar_set_int(&scalar_step, STEP);
  srand(time(NULL) + thread);
  rekey:

  randScalar7Bytes(&scalar_key, 0x05 + thread);

  /* Create group elements for both the random private key and the value 1 */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &base[STEP-1], &scalar_key);
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &temp, &scalar_one);
  secp256k1_ge_set_gej_var(&offset, &temp);

  /* Main Loop */
  printf("\r");  // This magically makes the loop faster by a smidge
  while(1) {
    /* Add 1 in Jacobian coordinates and save the result; repeat STEP times */
    my_secp256k1_gej_add_ge_var(&base[0], &base[STEP-1], &offset);
    for(k=1;k < STEP;k++)
      my_secp256k1_gej_add_ge_var(&base[k], &base[k-1], &offset);

    /* Convert all group elements from Jacobian to affine coordinates */
    my_secp256k1_ge_set_all_gej_var(rslt, base);

    for(k=0;k < STEP;k++) {
      thread_count[thread]++;

      /* Extract the 33-byte compressed public key from the group element */
      sha_block[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02);
      secp256k1_fe_get_b32(sha_block+1, &rslt[k].x);

      /* Hash public key */
      SHA256(sha_block, sizeof(sha_block), rmd_block);
      RIPEMD160(rmd_block, sizeof(rmd_block), pubkey);
      
      for(i=0;i < ADDRESS_NUM; i++) {
        if(0 == memcmp(pattern_to_find[i], pubkey, 15)) {
            secp256k1_scalar val1, val2;
            secp256k1_scalar_set_int(&val1, k+1);
            if (secp256k1_scalar_add(&val2, &scalar_key, &val1))
                printf("\nOverflow \n");
            secp256k1_scalar_get_b32((uint8_t*) key, &val2);
            printf("\nPrivate key found ");
            for(j=0;j < 32;j++) printf("%02x", result[j]);
            printf(" >>> ");
            for(;j < 52;j++) printf("%02x", result[j]);
            printf("\n");
            
            if(write(args->sock, result, 52) != 52)
                return NULL;
            
            //goto rekey;
        }
      }
    }

    /* Increment privkey by STEP */
    if (secp256k1_scalar_add(&scalar_key, &scalar_key, &scalar_step)) {
        printf("\nOverflow \n");
        goto rekey;
    }
  }
  return NULL;
}

// Returns 1 if the private key (first 32 bytes of 'result') correctly produces
// the public key (last 20 bytes of 'result').
//
static bool verify_key(const uint8_t result[52])
{
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar;
  secp256k1_gej gej;
  secp256k1_ge ge;
  uint8_t sha_block[SHA256_DIGEST_LENGTH+1], rmd_block[SHA256_DIGEST_LENGTH], pubkey[20];
  int ret, overflow;

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  /* Copy private key to secp256k1 scalar format */
  secp256k1_scalar_set_b32(&scalar, result, &overflow);
  if(overflow) {
    secp256k1_context_destroy(sec_ctx);
    return 0;  /* Invalid private key */
  }

  /* Create a group element for the private key we're verifying */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &gej, &scalar);

  /* Convert to affine coordinates */
  secp256k1_ge_set_gej_var(&ge, &gej);

  /* Extract the 33-byte compressed public key from the group element */
  sha_block[0]=(secp256k1_fe_is_odd(&ge.y) ? 0x03 : 0x02);
  secp256k1_fe_get_b32(sha_block+1, &ge.x);

  /* Hash public key */
  SHA256(sha_block, sizeof(sha_block), rmd_block);
  RIPEMD160(rmd_block, sizeof(rmd_block), pubkey);
  

  /* Verify that the hashed public key matches the result */
  ret=!memcmp(pubkey, result+32, 20);

  secp256k1_context_destroy(sec_ctx);
  return ret;
}


/**** libsecp256k1 Overrides *************************************************/

static void my_secp256k1_fe_inv_all_gej_var(secp256k1_fe *r,
                                            const secp256k1_gej *a)
{
  secp256k1_fe u;
  int i;

  r[0]=a[0].z;

  for(i=1;i < STEP;i++)
    secp256k1_fe_mul(&r[i], &r[i-1], &a[i].z);

  secp256k1_fe_inv_var(&u, &r[--i]);

  for(;i > 0;i--) {
    secp256k1_fe_mul(&r[i], &r[i-1], &u);
    secp256k1_fe_mul(&u, &u, &a[i].z);
  }

  r[0]=u;
}

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
                                            const secp256k1_gej *a)
{
  static secp256k1_fe azi[STEP];
  int i;

  my_secp256k1_fe_inv_all_gej_var(azi, a);

  for(i=0;i < STEP;i++)
    secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[i]);
}

static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
                                        const secp256k1_gej *a,
                                        const secp256k1_ge *b)
{
  /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
  secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

  secp256k1_fe_sqr(&z12, &a->z);
  u1 = a->x; secp256k1_fe_normalize_weak(&u1);
  secp256k1_fe_mul(&u2, &b->x, &z12);
  s1 = a->y; secp256k1_fe_normalize_weak(&s1);
  secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
  secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
  secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
  secp256k1_fe_sqr(&i2, &i);
  secp256k1_fe_sqr(&h2, &h);
  secp256k1_fe_mul(&h3, &h, &h2);
  secp256k1_fe_mul(&r->z, &a->z, &h);
  secp256k1_fe_mul(&t, &u1, &h2);
  r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3);
  secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
  secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t);
  secp256k1_fe_mul(&r->y, &r->y, &i);
  secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
  secp256k1_fe_add(&r->y, &h3);
}



///GPU
void printPlatformInfo(cl_platform_id platform_id) {
    char nbuf[256];
    size_t len;
    clGetPlatformInfo(platform_id, CL_PLATFORM_NAME, 256, nbuf,   &len);
    nbuf[len] =  '\0';
    printf("Platform info is ::: %s\n", nbuf);
}

void printDeviceInfo(cl_device_id device_id) {
    char name[256], vendor[256];
    cl_device_type type;
    cl_uint comp_units, freq;
    cl_ulong mem_size;
    size_t len;
    clGetDeviceInfo(device_id, CL_DEVICE_NAME, 256, name,   &len);
    name[len] =  '\0';
    clGetDeviceInfo(device_id, CL_DEVICE_VENDOR, 256, vendor, &len);
    vendor[len] =  '\0';

    clGetDeviceInfo(device_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(type), &type, NULL);
    clGetDeviceInfo(device_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(comp_units), &comp_units, NULL);
    clGetDeviceInfo(device_id, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(freq), &freq, NULL);
    clGetDeviceInfo(device_id, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(mem_size), &mem_size, NULL);

    printf("Device info is :\n\t--type: %ld, name: %s, vendor: %s\n\t--Compute units: %d, Frequency: %d, Memory size: %lu\n", type, name, vendor, comp_units, freq, mem_size);
}

char * getFileSource(const char *fileName) {
    char *fileBuffer;
    FILE *file = fopen(fileName, "r");
    if (!file)
    {
        fprintf(stderr, "Failed to open file %s\n", fileName);
        return NULL;
    }
    
    struct stat st;
    stat(fileName, &st);
    size_t fileSize = st.st_size;

    if (0 == fileSize)
    {
        fprintf(stderr, "%s source file is empty\n", fileName);
        return NULL;
    }
    
    fileBuffer = malloc(fileSize);
    size_t bytesRead = fread(fileBuffer, sizeof(char), fileSize, file);
    fclose(file);
    if (bytesRead != fileSize)
    {
        fprintf(stderr, "Failed to read complete source file %s\n", fileName);
        free(fileBuffer);
        return NULL;
    }
    return fileBuffer;
}

cl_program CreateProgram(cl_context context, cl_device_id device, const char *kernelFileName)
{
    cl_int errNum = 0;
    cl_program program;

    char *fileBuffers[2];
    
    fileBuffers[0] = getFileSource("secp256k1.cl");
    fileBuffers[1] = getFileSource(kernelFileName);
    
    program = clCreateProgramWithSource(context, 2, (const char **)fileBuffers, NULL, NULL);

    free(fileBuffers[0]);
    free(fileBuffers[1]);

    if (!program)
    {
        fprintf(stderr, "Failed to create program from source\n");
        return NULL;
    }

    errNum = clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
    if (CL_SUCCESS != errNum)
    {
        char buildLog[16384];
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof(buildLog), buildLog, NULL);
        fprintf(stderr, "Error when building program:\n%s\n", buildLog);
        clReleaseProgram(program);
        return NULL;
    }

    return program;
}

void workWithGPU() {
    const int LIST_SIZE = 128;
      cl_int res;
  cl_uint ret_num_devices;
  cl_device_id *device_id = NULL;
  
  cl_context ctx = NULL;
  cl_command_queue que = NULL;
  cl_program program = NULL;
  cl_kernel kernel = NULL;
  cl_mem mem_[] = {NULL, NULL, NULL};
  
    char hello1[LIST_SIZE + 14];
    char result[LIST_SIZE + 14];
  
  sprintf(hello1, "Hello kernel ");
  
  
//  res = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
  res = clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, 0, NULL, &ret_num_devices);
  if (res != CL_SUCCESS) {
      printf("Error: clGetDeviceIDs returns %d", res);
      goto error;
  }
  if (ret_num_devices< 1 || ret_num_devices > 50) {
      printf("Error: number of devices is out of range %d", ret_num_devices);
      goto error;
  }
      
  device_id = (cl_device_id *)malloc(sizeof(cl_device_id) * ret_num_devices);
  res = clGetDeviceIDs(NULL, CL_DEVICE_TYPE_ALL, ret_num_devices, device_id, &ret_num_devices);

  cl_uint i_ = 0;
  for (;i_ < ret_num_devices; i_++) {
      printf("%d::", i_);
      printDeviceInfo(device_id[i_]);
  }
  
  if (ret_num_devices > 1) {
      printf("Select device number \n");
      goto error;
  }
  
  ctx = clCreateContext(0, 1,&device_id[0],NULL, NULL, &res);
  printf("Create context returns %d\n", res);
  if (!ctx || res != CL_SUCCESS)
      goto error;
  
  //que = clCreateCommandQueue(ctx, &device_id[0], 0, &res);
  que = clCreateCommandQueueWithProperties(ctx, device_id[0], NULL, &res);
  if (!que || res != CL_SUCCESS) {
      printf("Failed to create queue\n");
      goto error;
  }
  
  program = CreateProgram(ctx, device_id[0], "HelloWorld.cl");
  if (!program)
  {
      printf("Failed to create program\n");
      goto error;
  }
  
  kernel = clCreateKernel(program, "hello_kernel", NULL);

  if (!kernel)
  {
      printf("Failed to create kernel\n");
      goto error;
  }

  int workSize = LIST_SIZE;
  size_t local_item_size = 64;
  size_t globalWorkSize[] = { LIST_SIZE };
  int i;


  
  mem_[0] = clCreateBuffer(ctx, CL_MEM_USE_HOST_PTR, sizeof(hello1), &hello1, NULL);
  clEnqueueWriteBuffer(que, mem_[0], CL_TRUE, 0, sizeof(hello1), hello1, 0, NULL, NULL);
  
    //cl_mem c_mem_obj = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, LIST_SIZE * sizeof(int), NULL, NULL);
    //res = clEnqueueWriteBuffer(que, a_mem_obj, CL_TRUE, 0, LIST_SIZE * sizeof(int), A, 0, NULL, NULL);
    //res = clEnqueueWriteBuffer(que, b_mem_obj, CL_TRUE, 0, LIST_SIZE * sizeof(int), B, 0, NULL, NULL);
        
  //res = clSetKernelArg(kernel, 0, sizeof(cl_mem), &mem_[0]);
  
    res = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&mem_[0]);
    
  if (res != CL_SUCCESS) {
      printf("Failed to set kernel argument\n");
      goto error;
  }

  printf("Buffer before run %s\n", hello1);
  
  cl_event ev;
  res = clEnqueueNDRangeKernel(que, kernel, 1, NULL, globalWorkSize, &local_item_size, 0, NULL, &ev);
  if (res != CL_SUCCESS) {
      printf("Failed to enqueue ND range\n");
      goto error;
  }
  
    clWaitForEvents(1, &ev);
	clReleaseEvent(ev);
  
  //res = clEnqueueReadBuffer(que, mem_[0], CL_TRUE, 0, sizeof(result), result, 0, NULL, NULL);
  //res = clEnqueueReadBuffer(que, c_mem_obj, CL_TRUE, 0, LIST_SIZE * sizeof(int), C, 0, NULL, NULL);

    // Display the result to the screen
    //for(i = 0; i < LIST_SIZE; i++) printf("%d + %d = %d\n", A[i], B[i], C[i]);
   
   printf("%s\n", result);
    printf("Buffer after run %s\n", hello1);
    
    return;
  error: 
    if (device_id) free(device_id);
    cleanupGPU(ctx, que, program, kernel, mem_);

  return;
}

void cleanupGPU(cl_context context, cl_command_queue commandQueue, cl_program program, cl_kernel kernel, cl_mem *memObjects) {
    if (commandQueue) {
        clFlush(commandQueue);
        clFinish(commandQueue);
        clReleaseCommandQueue(commandQueue);
    }
    if (kernel)
        clReleaseKernel(kernel);
    if (program)
        clReleaseProgram(program);
    if (context)
        clReleaseContext(context);

    for (int i = 0; i < 3; ++i)
    {
        if (memObjects[i])
        {
            clReleaseMemObject(memObjects[i]);
        }
    }
}