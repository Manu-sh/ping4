CXXFLAGS=-std=c++17 -Wall -Wextra -pedantic -pipe #-fstack-protector-strong
CXXFLAGS += -Ofast -march=native -mtune=native -ffast-math
LDLIBS=

.PHONY: all clean

all:
	$(CXX) $(CXXFLAGS) -o ping4 ping4.cpp $(LDLIBS)
	strip --strip-all ping4

clean:
	rm -f ping4
