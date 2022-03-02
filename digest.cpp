/*

g++ -std=c++11 -Wall -Wextra -flto -O3 digest.cpp -Wl,--dynamic-linker=/lib/ld.so -o digest -lboost_program_options -lboost_filesystem -lboost_system -lboost_date_time -lboost_regex -lcrypto -llzma

MinGW64
http://nuwen.net/files/mingw/mingw-12.2.exe
http://slproweb.com/download/Win64OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=bd2a6171-e2d6-4230-b809-9a8d7548c1b6
g++ -std=c++11 -Wall -Wextra -flto -O3 digest.cpp -o digest -lboost_program_options -lboost_filesystem -lboost_system libeay32.dll

MinGW32
http://jaist.dl.sourceforge.net/project/tdm-gcc/TDM-GCC%20Installer/Previous/1.1006.0/tdm-gcc-4.7.1-2.exe
http://slproweb.com/download/Win32OpenSSL-1_0_2.exe
http://www.microsoft.com/downloads/details.aspx?familyid=9B2DA534-3E03-4391-8A4D-074B9F2BC1BF
https://srgb.googlecode.com/files/sdk_boost_151.7z
g++ -std=c++11 -Wall -Wextra -flto -O3 digest.cpp -o digest libboost_program_options-mgw47-mt-1_51.a libboost_filesystem-mgw47-mt-1_51.a libboost_system-mgw47-mt-1_51.a libeay32.dll

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
#define STATE_F lstat64
#define OPEN open64
#define O_BINARY 0
#endif

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <lzma.h>
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
 
void print(std::string &o,std::map<std::string,md>::iterator x)
 {o+=(x->first+':');
  for(unsigned int i=0;i<x->second.size;i++)
   {o+=(boost::format("%02x")%((static_cast<short>(x->second.r[i])&0xFF))).str();
   }
  o+='\t';
 } 

typedef std::pair<dev_t,ino_t> file_t;
typedef std::set<std::string> names_t;
typedef std::map<ino_t,nlink_t> inos_t;
typedef std::string hash_t;

bool pick_a_name(const std::string &a,const std::string &b)
 {const size_t na=a.size();
  const size_t nb=b.size();
  if(nb>b.find_first_of('\x00')) return(true);
  else if(na>a.find_first_of('\x00')) return(false);
  else if(nb>b.find_first_of('\n')) return(true);
  else if(na>a.find_first_of('\n')) return(false);
  else if(nb>b.find_first_of('\t')) return(true);
  else if(na>a.find_first_of('\t')) return(false);
  else if(nb>b.find_first_of('\\')) return(true);
  else if(na>a.find_first_of('\\')) return(false);
  else if(nb>b.find_first_of('\'')) return(true);
  else if(na>a.find_first_of('\'')) return(false);
  else if(nb>b.find_first_of('\"')) return(true);
  else if(na>a.find_first_of('\"')) return(false);
  else if(na<nb) return(true);
  else if(nb<na) return(false);
  else return(a<b);
 }

void update_preferred_inode(inos_t::iterator p_new,std::pair<ino_t,inos_t> &i)
 {p_new->second++;
  inos_t::const_iterator p_old=i.second.find(i.first);
  assert(i.second.end()!=p_old);
  if(p_new->second > p_old->second) i.first=p_new->first;
 }

typedef std::map<dev_t,std::pair<ino_t,inos_t>> dev_inos_t;
typedef std::map<hash_t,dev_inos_t> hashs_map_t;

void digest(
std::map<file_t,std::tuple<nlink_t,hash_t,names_t>> &files_map,
hashs_map_t &hashs_map,
const bool m[9],const std::string &o_parent,const boost::filesystem::path &p,const struct STATE_S &s,const bool &c,std::map<std::string,md> &x)
 {//struct STATE_S s;
  //assert(0==STATE_F(p.c_str(),&s));
  //assert(S_ISREG(s.st_mode));
  const file_t file(std::make_pair(s.st_dev,s.st_ino));
  const std::string o_name(p.generic_string());
  const std::string dev_str(std::to_string(major(s.st_dev))+'_'+std::to_string(minor(s.st_dev))+'_');
  std::string o_meta;
  std::string o_hash;
  bool not_found=(files_map.end()==files_map.find(file));
  if(not_found) files_map.insert(std::make_pair(file,std::make_tuple(s.st_nlink,"",names_t({{o_name}}))));
  else
   {assert(std::get<2>(files_map[file]).end()==std::get<2>(files_map[file]).find(o_name));
    std::get<2>(files_map[file]).insert(o_name);
    hashs_map_t::iterator p1=hashs_map.find(std::get<1>(files_map[file]));
    assert(hashs_map.end()!=p1);
    dev_inos_t::iterator p2=p1->second.find(s.st_dev);
    assert(p1->second.end()!=p2);
    inos_t::iterator p_new=p2->second.second.find(s.st_ino);
    assert(p2->second.second.end()!=p_new);
    update_preferred_inode(p_new,p2->second);
   }
  if(m[0])
   {std::string o(o_name);
    assert(0==o.compare(0,o_parent.size(),o_parent));
    o.erase(0,o_parent.size());
    assert(1<=o.size());
    std::cout<<o<<"\t";
    assert(o.size()<=o.find_first_of('\t'));
    assert(o.size()<=o.find_first_of('\n'));
   }
  if(m[1]) std::cout<<dev_str<<s.st_ino<<'\t';
  if(m[2]) o_meta+=(boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_mtime))+'\t');
  if(m[3]) o_meta+=(boost::posix_time::to_iso_string(boost::posix_time::from_time_t(s.st_ctime))+'\t');
  if(m[4]) o_meta+=(std::to_string(s.st_nlink)+'\t');
  std::cout<<o_meta<<std::flush;
  if(m[5]) o_hash+=(std::to_string(s.st_size)+'\t');
  if(not_found)
   {if(c)
     {// boost::crc_32_type crc32_ieee; /* Very Slow */
      // boost::crc_optimal<64, 0x42F0E1EBA9EA3693ULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,false,false> crc64_ecma_182 ; /* Very Slow */
      for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++)
       {assert(1==EVP_MD_CTX_reset(m->second.c));
        if(1!=EVP_DigestInit_ex(m->second.c,m->second.m,NULL))
         {std::cerr<<ERR_error_string(ERR_get_error(),NULL)<<" : "<<EVP_MD_name(m->second.m)<<std::endl;
          std::abort();
         }
       }
      const off64_t block_size = 64*sysconf(_SC_PAGESIZE); // 64*4096
      //const off64_t block_size = s.st_size;
      int f;
      off64_t fsize;
      uint32_t crc32=0UL;
      uint64_t crc64=0ULL;
      assert(-1!=(f=OPEN(p.c_str(),O_RDONLY|O_BINARY)));
      uint8_t *mem;
      for(fsize=0;fsize<s.st_size;fsize+=block_size)
       {off64_t readed=(fsize+block_size<=s.st_size?block_size:(s.st_size-fsize));
        assert(MAP_FAILED!=(mem=(uint8_t*)mmap(NULL,readed,PROT_READ,MAP_SHARED,f,fsize)));
        if(m[6]) crc32=lzma_crc32(mem,readed,crc32);
        if(m[7]) crc64=lzma_crc64(mem,readed,crc64);
        for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) assert(1==EVP_DigestUpdate(m->second.c,mem,readed));
        assert(0==munmap(mem,readed));
       }
      close(f);
      for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) assert(1==EVP_DigestFinal_ex(m->second.c,m->second.r,&(m->second.size)));
      if(m[6]) o_hash+=("CRC32:"+(boost::format("%08lX")%crc32).str()+'\t');
      if(m[7]) o_hash+=("CRC64:"+(boost::format("%016lX")%crc64).str()+'\t');
      for(std::map<std::string,md>::iterator m=x.begin();m!=x.end();m++) print(o_hash,m);
     }
    if(1<=o_hash.size())
     {assert(2<=o_hash.size() && '\t'==o_hash[o_hash.size()-1]);
      o_hash.resize(o_hash.size()-1);
     }
    std::get<1>(files_map[file])=o_hash;
    if(m[8]) std::cout<<o_hash<<'\n';
    hashs_map_t::iterator p1=hashs_map.find(o_hash);
    if(hashs_map.end()==p1) hashs_map.insert(std::make_pair(o_hash,dev_inos_t({{s.st_dev,std::make_pair(s.st_ino,inos_t({{s.st_ino,1}}))}})));
    else
     {dev_inos_t::iterator p2=p1->second.find(s.st_dev);
      if(p1->second.end()==p2) p1->second.insert(std::make_pair(s.st_dev,std::make_pair(s.st_ino,inos_t({{s.st_ino,1}}))));
      else
       {inos_t::iterator p3=p2->second.second.find(s.st_ino);
        if(p2->second.second.end()==p3)
         {assert(1<=p2->second.second.size());
          p2->second.second.insert(std::make_pair(s.st_ino,1));
         }
        else
         {assert(!"should never reach here, because files_map stores redundant inode information, it should go through checks there");
          update_preferred_inode(p3,p2->second);
         }
       }
     }
   }
  else if(m[8]) std::cout<<std::get<1>(files_map[file])<<'\n';
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
 {boost::program_options::options_description desc(std::string("Example:\n  ")+argv[0]+" -c 1 -h SHA3-256 -m 36mcslni --list-found-incompletely --tell-what-to-link --do-deduplicate=0 \n");
  std::vector<boost::filesystem::path> paths;
  bool b;
  std::string x1;
  bool m[9];
  std::string m0;
  std::string o;
  bool c;
  bool f;
  bool list_found_incompletely;
  bool tell_what_to_link;
  bool do_deduplicate;
  std::set<std::string> MDs;
  OpenSSL_add_all_digests();
  EVP_MD_do_all(list_available_digest,&MDs);
  std::string h;
  desc.add_options()
   ("help,?", "1.2.1.2")
   ("path,p",boost::program_options::value<std::vector<boost::filesystem::path> >(&paths)->default_value(std::vector<boost::filesystem::path>(1,"."),"."),"Where to Traversal")
   ("basename,b", boost::program_options::value<bool>(&b)->default_value(true),"Trim prefix path")
   ("exclude,x",boost::program_options::value<std::string>(&x1)->default_value(""),"Exclude basename match regex")
   ("mask,m", boost::program_options::value<std::string>(&m0)->default_value(""),"Mask Output: (n)ame,(i)node,(m)time,(c)time,(l)inks,(s)ize,crc(3)2,crc(6)4,(h)ashs")
   ("out,o",boost::program_options::value<std::string>(&o)->default_value("-"),"Output")
   ("regular_file_only,f", boost::program_options::value<bool>(&f)->default_value(true),"Exception of non-regular_file")
   ("content,c", boost::program_options::value<bool>(&c)->default_value(false),"Calculate file digest")
   ("digests,h", boost::program_options::value<std::string>(&h)->default_value(boost::algorithm::join(MDs,",")),"Digests to be selected")
   ("list-found-incompletely",boost::program_options::bool_switch(&list_found_incompletely)->default_value(false),"inodes found in traverse < file system indicates nlinks")
   ("tell-what-to-link",boost::program_options::bool_switch(&tell_what_to_link)->default_value(false),"list duplicate files to be link")
   ("do-deduplicate",boost::program_options::value<bool>(&do_deduplicate)->default_value(false),"make hard links on duplicate files")
   ;
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
    m[1]=(m0.size()<=m0.find_first_of('i'));
    m[2]=(m0.size()<=m0.find_first_of('m'));
    m[3]=(m0.size()<=m0.find_first_of('c'));
    m[4]=(m0.size()<=m0.find_first_of('l'));
    m[5]=(m0.size()<=m0.find_first_of('s'));
    m[6]=(m0.size()<=m0.find_first_of('3'));
    m[7]=(m0.size()<=m0.find_first_of('6'));
    m[8]=(m0.size()<=m0.find_first_of('h'));
    std::map<std::string,md> x;
    if(c&&!h.empty())
     {for(boost::split_iterator<std::string::iterator> i=boost::make_split_iterator(h,boost::algorithm::token_finder(boost::is_any_of(", "),boost::token_compress_on));i!=boost::split_iterator<std::string::iterator>();i++)
       {const EVP_MD *m=NULL;
        assert(NULL!=(m=EVP_get_digestbyname(boost::copy_range<std::string>(*i).c_str())));
        EVP_MD_CTX *c=NULL;
        assert(NULL!=(c=EVP_MD_CTX_new()));
        x.insert(std::pair<std::string,md>(EVP_MD_name(m),md(m,c)));
       }
     }
    const boost::regex x2(x1);
    std::map<file_t,std::tuple<nlink_t,hash_t,names_t>> files_map;
    hashs_map_t hashs_map;
    std::set<boost::filesystem::path> paths1;
    for(std::vector<boost::filesystem::path>::const_iterator p=paths.begin();p!=paths.end();p++) paths1.insert(boost::filesystem::canonical(*p));
    for(std::set<boost::filesystem::path>::const_iterator p=paths1.begin();p!=paths1.end();p++)
     {struct STATE_S s;
      assert(0==STATE_F(p->c_str(),&s));
      const std::string n(b?(S_ISDIR(s.st_mode)?p->generic_string()+'/':(S_ISREG(s.st_mode)?p->parent_path().generic_string()+'/':"")):"");
      if(S_ISREG(s.st_mode)) digest(files_map,hashs_map,m,n,*p,s,c,x);
      else
       {for (boost::filesystem::recursive_directory_iterator i(*p),e; i!=e; i++)
         {assert(0==STATE_F(i->path().c_str(),&s));
          if(S_ISREG(s.st_mode))
           {if(x1.empty()||!boost::regex_match(basename(i->path().c_str()),x2)) digest(files_map,hashs_map,m,n,i->path(),s,c,x);
           }
          else
           {if(S_ISDIR(s.st_mode)){}
            else
             {if(f)
               {// symlink_to_(file|notfound) (in|out)_traverse && 1==r => Exception
                // symlink_to_(file|notfound) (in|out)_traverse && 0==r => Ignore && OK
                // symlink_to_dir (in|out)_traverse && (0|1)==r => Ignore && OK
                std::cerr<<"NOT a regular file: "<<i->path()<<std::endl;
                assert(S_ISREG(s.st_mode));
               }
             }
           }
         }
       }
     }
    hashs_map_t::const_iterator p1;
    for(p1=hashs_map.begin();hashs_map.end()!=p1;p1++)
     {dev_inos_t::const_iterator p2;
      for(p2=p1->second.begin();p1->second.end()!=p2;p2++)
       {std::map<file_t,std::tuple<nlink_t,hash_t,names_t>>::const_iterator p3=files_map.find(std::make_pair(p2->first,p2->second.first));
        assert(files_map.end()!=p3);
        const names_t &n=std::get<2>(p3->second);
        //std::vector<std::string> sorted_names(n.size());
        std::vector<std::string> sorted_names(1);
        std::partial_sort_copy(n.begin(),n.end(),sorted_names.begin(),sorted_names.end(),pick_a_name);
        //std::copy(sorted_names.begin(),sorted_names.end(),std::ostream_iterator<std::string>(std::cout,"\n"));
        const std::string &a_name=sorted_names[0];
        bool found=false;
        inos_t::const_iterator p4;
        for(p4=p2->second.second.begin();p2->second.second.end()!=p4;p4++)
         {std::map<file_t,std::tuple<nlink_t,hash_t,names_t>>::const_iterator p5=files_map.find(std::make_pair(p2->first,p4->first));
          assert(files_map.end()!=p5);
          assert(std::get<2>(p5->second).size()==p4->second);
          if(list_found_incompletely)
           {const nlink_t n=std::get<0>(p5->second);
            if(n!=p4->second)
             {std::cout<<'\t'<<'\t'<<major(p2->first)<<'_'<<minor(p2->first)<<'_'<<p4->first<<'\t'<<p4->second<<'<'<<n<<'\n';
              assert(n>p4->second);
             }
           }
          if(p2->second.first==p4->first) found=true;
          else if(2<=p2->second.second.size())
           {//std::cout<<'\t'<<p1->first<<'\t'<<major(p2->first)<<'_'<<minor(p2->first)<<'\t'<<p2->second.first<<'\t'<<p4->first<<'\t'<<p4->second<<'\n';
            if(c&&!h.empty()&&(tell_what_to_link||do_deduplicate))
             {names_t::const_iterator e=std::get<2>(p5->second).end();
              for(names_t::const_iterator t=std::get<2>(p5->second).begin();e!=t;t++)
               {if(tell_what_to_link) std::cout<<'\t'<<"ln -f"<<'\t'<<a_name<<'\t'<<*t<<'\n';
                if(do_deduplicate)
                 {assert(0==unlink(t->c_str()));
                  assert(0==link(a_name.c_str(),t->c_str()));
                 }
               }
             }
           }
         }
        assert(true==found);
       }
     }
    fclose(stdout);
    return(0);
   }
 }

