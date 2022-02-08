/*

g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest -lboost_program_options -lboost_filesystem -lboost_system -lboost_date_time -lboost_regex -lcrypto

MinGW64
http://nuwen.net/files/mingw/mingw-12.2.exe
http://slproweb.com/download/Win64OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=bd2a6171-e2d6-4230-b809-9a8d7548c1b6
g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest -lboost_program_options -lboost_filesystem -lboost_system libeay32.dll

MinGW32
http://jaist.dl.sourceforge.net/project/tdm-gcc/TDM-GCC%20Installer/Previous/1.1006.0/tdm-gcc-4.7.1-2.exe
http://slproweb.com/download/Win32OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=9B2DA534-3E03-4391-8A4D-074B9F2BC1BF
https://srgb.googlecode.com/files/sdk_boost_151.7z
g++ -std=c++11 -Wall -Wextra -O3 digest.cpp -o digest libboost_program_options-mgw47-mt-1_51.a libboost_filesystem-mgw47-mt-1_51.a libboost_system-mgw47-mt-1_51.a libeay32.dll

# echo $(($(cat File | awk 'BEGIN{size=0}{size+=$4}END{print size}')*100/$(du -sb /Directory | cut -f1)))'%'

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
#define O_BINARY 0
#endif

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <boost/assert.hpp>
#include <boost/crc.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

struct md
 {const EVP_MD *m;
  EVP_MD_CTX *c;
  unsigned char r[EVP_MAX_MD_SIZE];
  unsigned int size;
  md(const EVP_MD *m,EVP_MD_CTX *c):m(m),c(c){}; 
  //~md(){EVP_MD_CTX_free(c);}; // Segmentation fault
 };
 
void print(std::map<std::string,md>::iterator x)
 {std::cout<<x->first<<':';
  for(unsigned int i=0;i<x->second.size;i++)
   {std::cout<<boost::format("%02x")%((static_cast<short>(x->second.r[i])&0xFF));
   }
  std::cout<<"\t";
 } 

void digest(const bool m[6],const std::string &b,const boost::filesystem::path &p,const bool &c,std::map<std::string,md> &x)
 {struct STATE_S s;
  assert(0==STATE_F(p.c_str(),&s));
  assert(S_ISREG(s.st_mode));
  if(m[0])
   {std::string o(p.generic_string());
    assert(0==o.compare(0,b.size(),b));
    o.erase(0,b.size());
    assert(1<=o.size());
    std::cout<<o<<"\t";
    assert(o.size()<o.find_first_of('\t'));
    assert(o.size()<o.find_first_of('\n'));
   }
  if(m[1]) std::cout<<major(s.st_dev)<<"_"<<minor(s.st_dev)<<"_"<<s.st_ino<<"\t";
  if(m[2]) std::cout<<boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_mtime))<<"\t";
  if(m[3]) std::cout<<boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_ctime))<<"\t";
  if(m[4]) std::cout<<s.st_nlink<<"\t";
  if(m[5]) std::cout<<s.st_size<<"\t";
  std::cout<<std::flush;
  if(c)
   {off64_t readed;
    boost::crc_32_type crc32_ieee;
    boost::crc_optimal<64, 0x42F0E1EBA9EA3693ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,false,false> crc64_ecma_182 ;
    for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++)
     {assert(1==EVP_MD_CTX_reset(m->second.c));
      if(1!=EVP_DigestInit_ex(m->second.c,m->second.m,NULL))
       {std::cerr<<ERR_error_string(ERR_get_error(),NULL)<<" : "<<EVP_MD_name(m->second.m)<<std::endl;
        std::abort();
       }
     }
    const size_t block_size=128;
    unsigned char buf[block_size];
    int f;
    off64_t fsize;
    assert(-1!=(f=OPEN(p.c_str(),O_RDONLY|O_BINARY)));
    for(fsize=0;(readed=read(f,buf,block_size))==block_size;fsize+=block_size)
     {crc32_ieee.process_bytes(buf,block_size);
      crc64_ecma_182.process_bytes(buf,block_size);
      for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) assert(EVP_DigestUpdate(m->second.c,buf,block_size)==1);
     }
    close(f);
    assert(fsize+readed==s.st_size);
    crc32_ieee.process_bytes(buf,readed);
    crc64_ecma_182.process_bytes(buf,readed);
    for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) assert(EVP_DigestUpdate(m->second.c,buf,readed)==1);
    for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++)
     {assert(EVP_DigestFinal_ex(m->second.c,m->second.r,&(m->second.size))==1);
      //EVP_MD_CTX_free(m->second.c);
     }
    std::cout<<"CRC32:"<<boost::format("%08lX")%crc32_ieee.checksum()<<"\t";
    std::cout<<"CRC64:"<<boost::format("%016lX")%crc64_ecma_182.checksum()<<"\t";
    for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) print(m);
   }
  std::cout<<"\n";
 }

void list_available_digest(const EVP_MD *m, const char *from, const char*, void *arg)
{std::set<std::string> *MDs=(std::set<std::string>*)arg;
 if(m)
  {static const std::set<std::string> ignore=
    {"md5-sha1",
     "blake2s256",
     "blake2b512",
     "sha512-224",
     "sha512-256"
    };
   if(ignore.end()==ignore.find(from))
    {static const boost::regex e("(?:SM3|SHA512|SHA384|SHA224|MD4|RIPEMD160|SHA256|SHAKE128|whirlpool|SHA3-256|SHAKE256|MDC2|SHA3-224|SHA3-512|SHA3-384|MD5|SHA1)");
     const char *s=EVP_MD_name(m);
     if(boost::regex_match(s,e))
      {assert(MDs->end()==MDs->find(s));
       assert(0==strcasecmp(from,s));
       MDs->insert(s);
      }
     else
      {std::cerr<<"UnKnown: "<<s<<'\n';
       std::abort();
      }
    }
  }
}

int main(int argc, char *argv[])
 {boost::program_options::options_description desc;
  std::vector<boost::filesystem::path> paths;
  bool b;
  bool m[6];
  std::string m0;
  std::string o;
  bool c;
  bool r;
  std::set<std::string> MDs;
  OpenSSL_add_all_digests();
  EVP_MD_do_all(list_available_digest,&MDs);
  std::string s;
  desc.add_options()
   ("help,h", "1.1.2.1")
   ("path,p",boost::program_options::value<std::vector<boost::filesystem::path> >(&paths)->default_value(std::vector<boost::filesystem::path>(1,"."),"."),"Where to Traversal")
   ("basename,b", boost::program_options::value<bool>(&b)->default_value(true),"Trim prefix path")
   ("mask,m", boost::program_options::value<std::string>(&m0)->default_value(""),"Mask Output: (n)ame,(d)evice,(m)time,(c)time,(l)inks,(s)ize")
   ("out,o",boost::program_options::value<std::string>(&o)->default_value("-"),"Output")
   ("regular_file_only,r", boost::program_options::value<bool>(&r)->default_value(true),"Exception of non-regular_file")
   ("content,c", boost::program_options::value<bool>(&c)->default_value(false),"Calculate file digest")
   ("digests,s", boost::program_options::value<std::string>(&s)->default_value(boost::algorithm::join(MDs,",")),"Digests to be selected");
  MDs.clear();
  boost::program_options::positional_options_description pd;
  pd.add("path",-1);
  boost::program_options::variables_map vm;
  boost::program_options::store(boost::program_options::command_line_parser(argc,argv).options(desc).positional(pd).run(),vm);
  boost::program_options::notify(vm);
  if(vm.count("help"))
   {std::cerr<<desc<<"\n";
    return(1);
   }
  else
   {if("-"!=o)
     {assert(freopen(o.c_str(),"w",stdout));
     }
    m[0]=(m0.size()<=m0.find_first_of('n'));
    m[1]=(m0.size()<=m0.find_first_of('d'));
    m[2]=(m0.size()<=m0.find_first_of('m'));
    m[3]=(m0.size()<=m0.find_first_of('c'));
    m[4]=(m0.size()<=m0.find_first_of('l'));
    m[5]=(m0.size()<=m0.find_first_of('s'));
    std::map<std::string,md> x;
    if(c&&!s.empty())
     {for(boost::split_iterator<std::string::iterator> i=boost::make_split_iterator(s,boost::algorithm::token_finder(boost::is_any_of(", "),boost::token_compress_on));i!=boost::split_iterator<std::string::iterator>();i++)
       {const EVP_MD *m=NULL;
        assert(NULL!=(m=EVP_get_digestbyname(boost::copy_range<std::string>(*i).c_str())));
        EVP_MD_CTX *c=NULL;
        assert(NULL!=(c=EVP_MD_CTX_new()));
        x.insert(std::pair<std::string,md>(EVP_MD_name(m),md(m,c)));
       }
     }
    std::set<boost::filesystem::path> paths1;
    for(std::vector<boost::filesystem::path>::const_iterator p=paths.begin();p!=paths.end();p++) paths1.insert(boost::filesystem::canonical(*p));
    for(std::set<boost::filesystem::path>::const_iterator p=paths1.begin();p!=paths1.end();p++)
     {std::string n("") ;
      if(b)
       {if(boost::filesystem::is_directory(*p))
         {n=p->generic_string();
         }
        else if(boost::filesystem::is_regular_file(*p))
         {n=p->parent_path().generic_string();
         }
        n+='/';
       }
      if(boost::filesystem::is_regular_file(*p)) digest(m,n,*p,c,x);
      else
       {for (boost::filesystem::recursive_directory_iterator i(*p),e; i!=e; i++)
         {if(boost::filesystem::is_directory(i->path())){}
          else if(boost::filesystem::is_regular_file(i->path())) digest(m,n,i->path(),c,x);
          else
           {if(r)
             {std::map<boost::filesystem::file_type,std::string> s=
               {{boost::filesystem::status_unknown,"status_unknown"},
                {boost::filesystem::status_error,"status_error"},
                {boost::filesystem::file_not_found,"file_not_found"},
                {boost::filesystem::regular_file,"regular_file"},
                {boost::filesystem::directory_file,"directory_file"},
                {boost::filesystem::symlink_file,"symlink_file"},
                {boost::filesystem::block_file,"block_file"},
                {boost::filesystem::character_file,"character_file"},
                {boost::filesystem::fifo_file,"fifo_file"},
                {boost::filesystem::socket_file,"socket_file"},
                {boost::filesystem::reparse_file,"reparse_file"},
                {boost::filesystem::type_unknown,"type_unknown"}
               };
              std::cerr<<"NOT a regular file: "<<i->path()<<" : file_type="<<s[boost::filesystem::status(i->path()).type()]<<std::endl;
              assert(boost::filesystem::is_regular_file(i->path()));
             }
           }
         }
       }
     }
    fclose(stdout);
    return(0);
   }
 }

