# MinGW 32-bit matches legacy QQ Common.dll / IM.dll builds.
CXX ?= i686-w64-mingw32-gcc

envelope_qq2009.exe: envelope_qq2009.c
	$(CXX) -Wall -Wextra -O2 -s -o $@ $<

clean:
	rm -f envelope_qq2009.exe
