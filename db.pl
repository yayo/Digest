
print('BEGIN TRANSACTION;'."\n");
print('PRAGMA foreign_keys = ON;'."\n");

while (<STDIN>)
 {
  if($_ !~ /^([^\t]*?)\t([0-9]{14})\t([0-9]{14})\t([0-9]{1,})\tCRC32:([0-9A-F]{8})\tMD5:([0-9a-f]{32})\tRIPEMD160:([0-9a-f]{40})\tSHA1:([0-9a-f]{40})\tSHA256:([0-9a-f]{64})\tSHA512:([0-9a-f]{128})\twhirlpool:([0-9a-f]{128})\t\r\n$/)
   {die($_);
   }
  else
   {
    my ($name,$mtime,$ctime,$size,$crc32,$md5,$ripemd160,$sha1,$sha256,$sha512,$whirlpool)=($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11);
    $name =~ s/'/''/g;
    # print('INSERT into input(name) values(\''.$1.'\');'."\n" );
    # print('INSERT OR IGNORE into crc32(crc32) values(X\''.$5.'\');'."\n" );
    # print('INSERT OR IGNORE into md5(md5) values(x\''.$6.'\');'."\n" );
    # print('INSERT OR IGNORE into ripemd160(ripemd160) values(x\''.$7.'\');'."\n" );
    # print('INSERT OR IGNORE into sha1(sha1) values(x\''.$8.'\');'."\n" );
    # print('INSERT OR IGNORE into sha256(sha256) values(x\''.$9.'\');'."\n" );
    # print('INSERT OR IGNORE into sha512(sha512) values(x\''.$10.'\');'."\n" );
    # print('INSERT into loading(name,mtime,ctime,size,crc32,md5,ripemd160,sha1,sha256,sha512) values((select id from input where name=\''.$1.'\'),'.$2.','.$3.','.$4.',(select id from crc32 where crc32=X\''.$5.'\'),(select id from md5 where md5=X\''.$6.'\'),(select id from ripemd160 where ripemd160=X\''.$7.'\'),(select id from sha1 where sha1=X\''.$8.'\'),(select id from sha256 where sha256=X\''.$9.'\'),(select id from sha512 where sha512=X\''.$10.'\'));'."\n" );
    print('INSERT into loading(name,mtime,ctime,size,crc32,md5,ripemd160,sha1,sha256,sha512,whirlpool) values(\''.$name.'\','.$mtime.','.$ctime.','.$size.',X\''.$crc32.'\',x\''.$md5.'\',x\''.$ripemd160.'\',x\''.$sha1.'\',x\''.$sha256.'\',x\''.$sha512.'\',x\''.$whirlpool.'\');'."\n" );

   }
 }
print('COMMIT;'."\n");
