/*

http://download.microsoft.com/download/d/2/4/d242c3fb-da5a-4542-ad66-f9661d0a8d19/vcredist_x64.exe
http://slproweb.com/download/Win64OpenSSL-1_0_1g.exe
http://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/4.8.2/threads-posix/seh/x86_64-4.8.2-release-posix-seh-rt_v3-rev3.7z/download

g++ -Wall -Wextra digest.cpp libeay32.dll -lz -o digest.exe

*/

#include <Windows.h>
#include <malloc.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <map>
#include <string>
#include <algorithm>

#undef PATH_MAX
#define PATH_MAX 1024

struct md
 {const EVP_MD *md;
  EVP_MD_CTX *ctx;
  unsigned char r[EVP_MAX_MD_SIZE];
  unsigned int size;
 };
 
void init(std::map<std::string,md>::iterator x)
 {x->second.md=NULL;
  assert(NULL!=(x->second.md=EVP_get_digestbyname(x->first.c_str())));
  x->second.ctx=NULL;
  assert(NULL!=(x->second.ctx=EVP_MD_CTX_create()));
  assert(1==EVP_DigestInit_ex(x->second.ctx, x->second.md, NULL));
 }

void update(std::map<std::string,md>::iterator x,unsigned char *buf,const size_t size)
 {assert(EVP_DigestUpdate(x->second.ctx, buf, size)==1);
 }

void final(std::map<std::string,md>::iterator x)
 {assert(EVP_DigestFinal_ex(x->second.ctx, x->second.r,&(x->second.size))==1);
  EVP_MD_CTX_destroy(x->second.ctx);
  x->second.ctx=NULL;
 } 

void print(std::map<std::string,md>::iterator x)
 {fprintf(stdout,"%s:",EVP_MD_name(x->second.md));
  for(unsigned int i=0;i<x->second.size;i++)
   {fprintf(stdout,"%02x",x->second.r[i]);
   }
  fprintf(stdout,"\t");
 } 

int traversal(const wchar_t *d,FILE *f,bool r)
 {_WDIR *dp;
  _wdirent *ep;
  assert(dp=_wopendir(d));
  for(;(ep=_wreaddir(dp));)
   {
    wchar_t fname[PATH_MAX+1];
    //wchar_t *fname=(wchar_t*)malloc((PATH_MAX+1)*sizeof(wchar_t));
    //wchar_t *fname=(wchar_t*)_alloca((PATH_MAX+1)*sizeof(wchar_t));
    //wchar_t *fname=new wchar_t[PATH_MAX+1];
    wcscpy(fname,d);
    wcscat(fname,L"\\");
    wcscat(fname,ep->d_name);
    struct _stat64 s;
    assert(_wstat64(fname,&s)==0);
    if(S_ISDIR(s.st_mode))
     {if(!(((ep->d_name)[0]=='.'&&(ep->d_name)[1]==0)||((ep->d_name)[0]=='.'&&(ep->d_name)[1]=='.'&&(ep->d_name)[2]==0)))
       {traversal(fname,f,r); 
       }
     }
    else
     {
      if(!S_ISREG(s.st_mode))
       {assert(fname);}
      else
       {off64_t i;
        char fname_UTF8[(PATH_MAX+1)*4];
        //char *fname_UTF8=(char*)_alloca((PATH_MAX+1)*sizeof(char)*4);
        //fprintf(stdout,"%d\t",wcslen(fname));
        //fwprintf(stdout,L"%s\t",fname);
        //memset (fname_UTF8,0,(PATH_MAX+1)*4);
        assert(0<WideCharToMultiByte( CP_UTF8, 0, fname, -1, fname_UTF8, (PATH_MAX+1)*4, NULL, NULL )); /* TAB CAN NOT BE A VALID FILENAME */
        fprintf(stdout,"%s\t",fname_UTF8);
        uLong crc=crc32(0L,Z_NULL,0);
        std::map<std::string,md> x;
        x["MD5"]=md();
        x["SHA1"]=md();
        x["SHA256"]=md();
        x["SHA512"]=md();
        x["RIPEMD160"]=md();
        for(std::map<std::string,md>::iterator it=x.begin();it!=x.end();it++) init(it);
        const size_t block_size=128;
        unsigned char buf[block_size];
        if(r)
         {int fi;
          off64_t fsize;
          assert(-1!=(fi=_wopen(fname,O_RDONLY|_O_BINARY)));
          for(fsize=0;(i=read(fi,buf,block_size))==block_size;fsize+=block_size)
           {crc = crc32(crc, buf, block_size);
            for(std::map<std::string,md>::iterator it=x.begin();it!=x.end();it++) update(it,buf,block_size);
           }
          close(fi);
          assert(fsize+i==s.st_size);
          crc=crc32(crc, buf, i);
          for(std::map<std::string,md>::iterator it=x.begin();it!=x.end();it++) update(it,buf,i);
          for(std::map<std::string,md>::iterator it=x.begin();it!=x.end();it++) final(it);
         }
        strftime((char*)fname,block_size,"%Y%m%d%H%M%S",localtime(&(s.st_mtime)));
        fprintf(stdout,"%s\t",(char*)fname);
        strftime((char*)fname,block_size,"%Y%m%d%H%M%S",localtime(&(s.st_ctime)));
        fprintf(stdout,"%s\t",(char*)fname);
        fprintf(stdout,"%I64d\t",s.st_size/*,s.st_ctime_usec*/);
        fprintf(stdout,"CRC32:%08lX\t",crc);
        for(std::map<std::string,md>::iterator it=x.begin();it!=x.end();it++) print(it);

        fprintf(stdout,"\n");
        fflush(stdout);
        //fprintf(stdout," %d,%d,%d\n",block_size,EVP_MAX_MD_SIZE,size);
       }
     }
    //free(fname);
    //delete []fname;
   }
  _wclosedir(dp);
  return(0);
 }

int main(int argc,char *argv[])
 {wchar_t d[PATH_MAX+1];
  if(argc<2)
   {wcscpy(d,L"");}
  else
   {MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,argv[1],-1,d,PATH_MAX);
    if(argc>=3)
     {if(argv[2][0]=='-' && argv[2][1]==0 )
       {
       }
      else
       {assert(freopen(argv[2],"w",stdout));
       }
      bool r;
      if(argc==4)
       {if(stricmp(argv[3],"0")==0)
         {r=false;}
        else
         {r=true;}
       }
      OpenSSL_add_all_digests();
      traversal(d,stdout,r);
      fclose(stdout);
     }
   }
   return(0);
 }
