
BEGIN TRANSACTION;
PRAGMA foreign_keys = ON;
create table name(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR NOT NULL UNIQUE);
create table crc32(id INTEGER PRIMARY KEY AUTOINCREMENT, crc32 blob(4) NOT NULL UNIQUE check(4=length(crc32)) );
create table md5(id INTEGER PRIMARY KEY AUTOINCREMENT, md5 blob(16) NOT NULL UNIQUE check(16=length(md5)) );
create table ripemd160(id INTEGER PRIMARY KEY AUTOINCREMENT, ripemd160 blob(20) NOT NULL UNIQUE check(20=length(ripemd160)) );
create table sha1(id INTEGER PRIMARY KEY AUTOINCREMENT, sha1  blob(20)  NOT NULL UNIQUE check(20=length(sha1)) );
create table sha256(id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 blob(32) NOT NULL UNIQUE check(32=length(sha256)) );
create table sha512(id INTEGER PRIMARY KEY AUTOINCREMENT, sha512 blob(64) NOT NULL UNIQUE check(64=length(sha512)) );
create table whirlpool(id INTEGER PRIMARY KEY AUTOINCREMENT, whirlpool blob(64) NOT NULL UNIQUE check(64=length(whirlpool)) );
create table load(id INTEGER PRIMARY KEY AUTOINCREMENT, time INT8 NOT NULL UNIQUE default(strftime('%Y%m%d%H%M%S')), prefix VARCHAR NOT NULL, memo VARCHAR NOT NULL);
create table file
 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
  deleted INT1 not null default 0,
  name INTEGER NOT NULL REFERENCES name(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED, mtime INT8 NOT NULL check(0<=mtime), 
  ctime INT8 NOT NULL check(0<=ctime), 
  size INT8 NOT NULL check(0<=size), 
  crc32 INTEGER NULL REFERENCES crc32(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  md5 INTEGER NULL REFERENCES md5(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  ripemd160 INTEGER NULL REFERENCES ripemd160(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  sha1 INTEGER NULL REFERENCES sha1(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  sha256 INTEGER NULL REFERENCES sha256(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  sha512 INTEGER NULL REFERENCES sha512(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  whirlpool INTEGER NULL REFERENCES whirlpool(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,
  UNIQUE(name,mtime),
  check(md5 is not null or ripemd160 is not null or sha1 is not null or sha256 is not null or sha512 is not null or whirlpool is not null)
 );
create table loaded(load INTEGER NOT NULL REFERENCES load(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,file INTEGER NOT NULL REFERENCES file(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,PRIMARY KEY(load,file));
create table loading(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR NOT NULL,
mtime INT8 NOT NULL,
ctime INT8 NOT NULL,
size INT8 NOT NULL,
crc32 blob(4) NULL,
md5 blob(16) NULL,
ripemd160 blob(20),
sha1  blob(20) NULL,
sha256 blob(32) NULL,
sha512 blob(64) NULL,
whirlpool blob(64) NULL,
UNIQUE(name),
check(md5 is not null or ripemd160 is not null or sha1 is not null or sha256 is not null or sha512 is not null or whirlpool is not null)
);

create table tree(id INTEGER PRIMARY KEY);
create table constitute(tree INTEGER NOT NULL REFERENCES tree(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,file INTEGER NOT NULL REFERENCES file(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,primary key(tree,file));
create table directory(tree INTEGER NOT NULL REFERENCES tree(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,file INTEGER NOT NULL REFERENCES file(id) ON DELETE RESTRICT ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED,primary key(tree,file));

create view loading_conflict as select * from loading where exists(select * from file where file.name=(select id from name where name.name=loading.name) and file.mtime=loading.mtime and (file.size<>loading.size or file.crc32<>(select id from crc32 where crc32.crc32=loading.crc32) or file.md5<>(select id from md5 where md5.md5=loading.md5) or file.ripemd160<>(select id from ripemd160 where ripemd160.ripemd160=loading.ripemd160) or file.sha1<>(select id from sha1 where sha1.sha1=loading.sha1) or file.sha256<>(select id from sha256 where sha256.sha256=loading.sha256) or file.sha512<>(select id from sha512 where sha512.sha512=loading.sha512) or file.whirlpool<>(select id from whirlpool where whirlpool.whirlpool=loading.whirlpool)));
create view files as select file.id,name.name,mtime,ctime,size,hex(crc32.crc32) as crc32,hex(md5.md5) as md5,hex(ripemd160.ripemd160) as ripemd160,hex(sha1.sha1) as sha1,hex(sha256.sha256) as sha256,hex(sha512.sha512) as sha512,hex(whirlpool.whirlpool) as whirlpool from file inner join name on file.name=name.id inner join crc32 on file.crc32=crc32.id inner join md5 on file.md5=md5.id inner join ripemd160 on file.ripemd160=ripemd160.id inner join sha1 on file.sha1=sha1.id inner join sha256 on file.sha256=sha256.id inner join sha512 on file.sha512=sha512.id inner join whirlpool on file.whirlpool=whirlpool.id;
create view crc32_collision as select * from file as f1 inner join file as f2 on f1.crc32=f2.crc32 and (f1.size<>f2.size or f1.md5<>f2.md5 or f1.ripemd160<>f2.ripemd160 or f1.sha1<>f2.sha1 or f1.sha256<>f2.sha256 or f1.sha512<>f2.sha512 or f1.whirlpool<>f2.whirlpool);
create view md5_collision as select * from file as f1 inner join file as f2 on f1.md5=f2.md5 and (f1.size<>f2.size or f1.crc32<>f2.crc32 or f1.ripemd160<>f2.ripemd160 or f1.sha1<>f2.sha1 or f1.sha256<>f2.sha256 or f1.sha512<>f2.sha512 or f1.whirlpool<>f2.whirlpool);
create view sha512_collision as select * from file as f1 inner join file as f2 on f1.sha512=f2.sha512 and (f1.size<>f2.size or f1.crc32<>f2.crc32 or f1.md5<>f2.md5 or f1.ripemd160<>f2.ripemd160 or f1.sha1<>f2.sha1 or f1.sha256<>f2.sha256 or f1.whirlpool<>f2.whirlpool);
create view whirlpool_collision as select * from file as f1 inner join file as f2 on f1.whirlpool=f2.whirlpool and (f1.size<>f2.size or f1.crc32<>f2.crc32 or f1.md5<>f2.md5 or f1.ripemd160<>f2.ripemd160 or f1.sha1<>f2.sha1 or f1.sha256<>f2.sha256 or f1.sha512<>f2.sha512);
create view incomplete as select * from file where crc32 is null or md5 is null or ripemd160 is null or sha1 is null or sha256 is null or sha512 is null or whirlpool is null;
create view multi_version_files_not_tested as select count(*),name from file group by name having count(*)>1 order by 1 desc,2 asc;
create view crc32_unreferenced as select * from crc32 where not exists(select * from file where file.crc32=crc32.id);
create view greater_mtimes_exists_identical_content_file_with_less_mtime as select id from file where exists(select * from file as f1 where file.size=f1.size and file.crc32=f1.crc32 and file.md5=f1.md5 and file.ripemd160=f1.ripemd160 and file.sha1=f1.sha1 and file.sha256=f1.sha256 and file.sha512=f1.sha512 and file.whirlpool=f1.whirlpool group by size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool having count(*)>1 and file.mtime>min(f1.mtime));
create view longer_filenames_exists_identical_content_file_with_shorter_filename as select file.id from file inner join name on file.name=name.id where exists(select * from file as f1 inner join name as n1 on f1.name=n1.id where file.size=f1.size and file.crc32=f1.crc32 and file.md5=f1.md5 and file.ripemd160=f1.ripemd160 and file.sha1=f1.sha1 and file.sha256=f1.sha256 and file.sha512=f1.sha512 and file.whirlpool=f1.whirlpool group by size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool having count(*)>1 and length(name.name)>min(length(n1.name)));
create view greater_ctimes_exists_identical_content_file_with_less_ctime as select id from file where exists(select * from file as f1 where file.size=f1.size and file.crc32=f1.crc32 and file.md5=f1.md5 and file.ripemd160=f1.ripemd160 and file.sha1=f1.sha1 and file.sha256=f1.sha256 and file.sha512=f1.sha512 and file.whirlpool=f1.whirlpool group by size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool having count(*)>1 and file.ctime>min(f1.ctime));
create view filenames_exists_identical_content_file_alphabetically_preceding_filename as select file.id from file inner join name on file.name=name.id where exists(select * from file as f1 inner join name as n1 on f1.name=n1.id where file.size=f1.size and file.crc32=f1.crc32 and file.md5=f1.md5 and file.ripemd160=f1.ripemd160 and file.sha1=f1.sha1 and file.sha256=f1.sha256 and file.sha512=f1.sha512 and file.whirlpool=f1.whirlpool group by size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool having count(*)>1 and name.name>min(n1.name));
create view duplicate_files as select count(*),size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool,'{'||group_concat(name,',')||'}' from files group by size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool having count(*) >1 order by 1 desc, 2 asc, 3 asc, 4 asc;
/* create view  larger_filenames_exists_identical_content_file_with_less_filename */
COMMIT;

/*
del db
cat db.sql | sqlite3 db
cat acc.md.txt | perl db.pl | sqlite3 db
sqlite3 db "select * from loading_conflict;"
sqlite3 db "INSERT OR IGNORE into name(name) select name from loading;INSERT OR IGNORE into crc32(crc32) select crc32 from loading;INSERT OR IGNORE into md5(md5) select md5 from loading;INSERT OR IGNORE into ripemd160(ripemd160) select ripemd160 from loading;INSERT OR IGNORE into sha1(sha1) select sha1 from loading;INSERT OR IGNORE into sha256(sha256) select sha256 from loading;INSERT OR IGNORE into sha512(sha512) select sha512 from loading;INSERT OR IGNORE into whirlpool(whirlpool) select whirlpool from loading;"
sqlite3 db "INSERT OR IGNORE into file(name,mtime,ctime,size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool) select name.id,loading.mtime,loading.ctime,loading.size,crc32.id,md5.id,ripemd160.id,sha1.id,sha256.id,sha512.id,whirlpool.id from loading inner join name on loading.name=name.name inner join crc32 on loading.crc32=crc32.crc32 inner join md5 on loading.md5=md5.md5 inner join ripemd160 on loading.ripemd160=ripemd160.ripemd160 inner join sha1 on loading.sha1=sha1.sha1 inner join sha256 on loading.sha256=sha256.sha256 inner join sha512 on loading.sha512=sha512.sha512 inner join whirlpool on loading.whirlpool=whirlpool.whirlpool;"
sqlite3 db "INSERT into load(prefix,memo) values('','');"
sqlite3 db "select max(id) from load;"
sqlite3 db "INSERT into loaded(load,file) select ?,file.id from loading inner join file on loading.mtime=file.mtime inner join name on file.name=name.id where loading.name=name.name;"
sqlite3 db "delete from loading;update sqlite_sequence set seq=0 where name='loading';"
sqlite3 db "select name.name,mtime,ctime,size,'CRC32:'||hex(crc32.crc32),'MD5:'||lower(hex(md5.md5)),'RIPEMD160:'||lower(hex(ripemd160.ripemd160)),'SHA1:'||lower(hex(sha1.sha1)),'SHA256:'||lower(hex(sha256.sha256)),'SHA512:'||lower(hex(sha512.sha512)),'whirlpool:'||lower(hex(whirlpool.whirlpool)) from file inner join name on file.name=name.id inner join crc32 on file.crc32=crc32.id inner join md5 on file.md5=md5.id inner join ripemd160 on file.ripemd160=ripemd160.id inner join sha1 on file.sha1=sha1.id inner join sha256 on file.sha256=sha256.id inner join sha512 on file.sha512=sha512.id inner join whirlpool on file.whirlpool=whirlpool.id where exists(select * from loaded where loaded.file=file.id and loaded.load=? ) order by file.id;" | sed -e "s/|/\t/g" -e "s/$/\t/" > tmp1
fc /b acc.md.txt tmp1

select count(*) from file where exists(select * from loaded where loaded.file=file.id and load=2);
select name.name,mtime,ctime,size,hex(crc32.crc32) as crc32,hex(md5.md5) as md5,hex(ripemd160.ripemd160) as ripemd160,hex(sha1.sha1) as sha1,hex(sha256.sha256) as sha256,hex(sha512.sha512) as sha512,hex(whirlpool.whirlpool) as whirlpool from file inner join name on file.name=name.id inner join crc32 on file.crc32=crc32.id inner join md5 on file.md5=md5.id inner join ripemd160 on file.ripemd160=ripemd160.id inner join sha1 on file.sha1=sha1.id inner join sha256 on file.sha256=sha256.id inner join sha512 on file.sha512=sha512.id inner join whirlpool on file.whirlpool=whirlpool.id where exists(select * from loaded where loaded.file=file.id and load=2) and exists(select * from file as f2 where exists(select * from loaded where loaded.file=f2.id and load<>2) and f2.size=file.size and f2.crc32=file.crc32 and f2.md5=file.md5 and f2.ripemd160=file.ripemd160 and f2.sha1=file.sha1 and f2.sha256=file.sha256 and f2.sha512=file.sha512 and f2.whirlpool=file.whirlpool);

# 2? true_subset_of 1?
select id from file as f1 where exists(select * from loaded where loaded.file=f1.id and load=2?) and not exists(select * from file as f2 where exists(select * from loaded where loaded.file=f2.id and load=1?) and f1.name=f2.name and f1.mtime=f2.mtime and f1.ctime=f2.ctime and f1.size=f2.size and f1.crc32=f2.crc32 and f1.md5=f2.md5 and f1.ripemd160=f2.ripemd160 and f1.sha1=f2.sha1 and f1.sha256=f2.sha256 and f1.sha512=f2.sha512 and f1.whirlpool=f2.whirlpool) limit 1 ;

cat acc.md.txt | awk 'BEGIN { FS = "\t" } ; {print $1"\t"$4"\t"$3"\t"$2"\t"$5"\t"$6"\t"$7"\t"$8"\t"$9"\t"$10"\t\r"}' > x

select * from crc32 where not exists(select * from file where file.crc32=crc32.id and exists(select * from loaded where loaded.file=file.id and loaded.load<>1));
select * from file where not exists(select * from loaded where loaded.file=file.id and loaded.load<>1);

*/
