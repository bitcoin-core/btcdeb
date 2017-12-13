all: btcdeb btcc

kerl/kerl.o: kerl/kerl.h kerl/kerl.c
	gcc -c kerl/kerl.c -o kerl/kerl.o

btcdeb: kerl/kerl.o btcdeb.cpp bitcoin
	g++ -std=c++11 -I. -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment btcdeb.cpp kerl/kerl.o *.o crypto/*.o -o btcdeb -lreadline

btcc: btcc.cpp bitcoin
	g++ -std=c++11 -I. -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment btcc.cpp *.o crypto/*.o -o btcc

bitcoin: hash.o interpreter.o script.o script_error.o uint256.o utilstrencodings.o crypto

crypto: crypto/hmac_sha512.o crypto/ripemd160.o crypto/sha1.o crypto/sha256.o crypto/sha512.o

%.o: %.cpp %.h
	g++ -std=c++11 -I. -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<

clean:
	rm -f *.o crypto/*.o kerl/kerl.o btcdeb btcc
