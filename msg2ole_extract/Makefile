# MinGW-w64 cross-compile (Linux → Windows PE).
# Override on native Windows: make CXX=g++
CXX := x86_64-w64-mingw32-g++
CXXFLAGS ?= -std=c++17 -O2 -municode -Wall -Wextra
LDFLAGS ?= -static -lole32 -luuid -lshell32

msg2ole_extract.exe: msg2ole_extract.cpp
	$(CXX) $(CXXFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f msg2ole_extract.exe

.PHONY: clean
