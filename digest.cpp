/*

g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest -lboost_program_options -lboost_filesystem -lboost_system -lboost_date_time -lz -lcrypto

MinGW64
http://nuwen.net/files/mingw/mingw-12.2.exe
http://slproweb.com/download/Win64OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=bd2a6171-e2d6-4230-b809-9a8d7548c1b6
g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest -lboost_program_options -lboost_filesystem -lboost_system -lz libeay32.dll

MinGW32
http://jaist.dl.sourceforge.net/project/tdm-gcc/TDM-GCC%20Installer/Previous/1.1006.0/tdm-gcc-4.7.1-2.exe
http://slproweb.com/download/Win32OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=9B2DA534-3E03-4391-8A4D-074B9F2BC1BF
https://srgb.googlecode.com/files/sdk_boost_151.7z
http://liquidtelecom.dl.sourceforge.net/project/mingw/MinGW/Base/zlib/zlib-1.2.8/zlib-1.2.8-1-mingw32-dll.tar.lzma
g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest libboost_program_options-mgw47-mt-1_51.a libboost_filesystem-mgw47-mt-1_51.a libboost_system-mgw47-mt-1_51.a zlib1.dll libeay32.dll

*/

#ifdef __MINGW32__
#define STATE_S _stati64
#define STATE_F _wstati64
#define OPEN _wopen
#elif defined( __MINGW64__ )
#define STATE_S stat64
#define STATE_F _wstat64
#define OPEN _wopen
#else
#define STATE_S stat64
#define STATE_F stat64
#define OPEN open64
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>

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
 {std::cout<<EVP_MD_name(x->second.md)<<':';
  for(unsigned int i=0;i<x->second.size;i++)
   {std::cout<<boost::format("%02x")%((static_cast<short>(x->second.r[i])&0xFF));
   }
  std::cout<<"\t";
 } 

int main(int argc, char *argv[])
 {boost::program_options::options_description desc;
  boost::filesystem::path p;
  std::string o;
  bool c;
  std::string s;
  bool r;
  desc.add_options()
   ("help,h", "1.1.1.2")
   ("path,p",boost::program_options::value<boost::filesystem::path>(&p)->default_value("."),"Where to Traversal")
   ("out,o",boost::program_options::value<std::string>(&o)->default_value("-"),"Output")
   ("content,c", boost::program_options::value<bool>(&c)->default_value(false),"Calculate file digest")
   //("digests,s", boost::program_options::value<std::string>(&s)->default_value("crc32,md5,sha1,sha256,sha512,ripemd160,whirlpool"),"Digests to be selected")
   ("regular_file_only,r", boost::program_options::value<bool>(&r)->default_value(true),"Exception of non-regular_file");

  boost::program_options::variables_map vm;
  boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
  boost::program_options::notify(vm);
  if(vm.count("help"))
   {std::cerr<<desc<<"\n";
    return(1);
   }
  else
   {p=boost::filesystem::canonical(p);
    if("-"!=o)
     {assert(freopen(o.c_str(),"w",stdout));
     }
    OpenSSL_add_all_digests();
    for (boost::filesystem::recursive_directory_iterator i(p),e; i!=e; i++)
     {if(boost::filesystem::is_directory(i->path())){}
      else if(boost::filesystem::is_regular_file(i->path()))
       {struct STATE_S s;
        assert(0==STATE_F(i->path().c_str(),&s));
        assert(S_ISREG(s.st_mode));
        std::cout<<i->path()<<"\t";
        assert(i->path().native().size()<=i->path().native().find_first_of('"'));
        std::cout<<boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_mtime))<<"\t";
        std::cout<<boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_ctime))<<"\t";
        std::cout<<s.st_size<<"\t"<<std::flush;
        if(c)
         {off64_t readed;
          uLong crc=crc32(0L,Z_NULL,0);
          std::map<std::string,md> x;
          x["MD5"]=md();
          x["SHA1"]=md();
          x["SHA256"]=md();
          x["SHA512"]=md();
          x["RIPEMD160"]=md();
          x["whirlpool"]=md();
          for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) init(m);
          const size_t block_size=128;
          unsigned char buf[block_size];
          int f;
          off64_t fsize;
          assert(-1!=(f=OPEN(i->path().c_str(),O_RDONLY)));
          for(fsize=0;(readed=read(f,buf,block_size))==block_size;fsize+=block_size)
           {crc = crc32(crc, buf, block_size);
            for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) update(m,buf,block_size);
           }
          close(f);
          assert(fsize+readed==s.st_size);
          crc=crc32(crc, buf, readed);
          for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) update(m,buf,readed);
          for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) final(m);
          std::cout<<"CRC32:"<<boost::format("%08lX")%crc<<"\t";
          for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) print(m);
         }
        std::cout<<"\n";
       }
      else
       {if(r)
         {std::map<boost::filesystem::file_type,std::string> s=
           {{boost::filesystem::status_unknown,"status_unknown"},
            {boost::filesystem::file_not_found,"file_not_found"},
            {boost::filesystem::regular_file,"regular_file"},
            {boost::filesystem::directory_file,"directory_file"},
            {boost::filesystem::symlink_file,"symlink_file"},
            {boost::filesystem::block_file,"block_file"},
            {boost::filesystem::character_file,"character_file"},
            {boost::filesystem::fifo_file,"fifo_file"},
            {boost::filesystem::socket_file,"socket_file"},
            {boost::filesystem::reparse_file,"reparse_file"},
            {boost::filesystem::type_unknown,"type_unknown"},
            {boost::filesystem::_detail_directory_symlink,"_detail_directory_symlink"}
           };
          std::cerr<<"NOT a regular file: "<<i->path()<<" : file_type="<<s[boost::filesystem::status(i->path()).type()]<<std::endl;
          assert(boost::filesystem::is_regular_file(i->path()));
         }
       }
     }
    fclose(stdout);
    return(0);
   }
 }

