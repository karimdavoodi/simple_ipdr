CPP = g++
CPPFLAGS = -std=c++17
LDFLAGS = -lboost_system -lboost_filesystem 
#SRCS = $(wildcard src/*.cpp) 
#OBJS = $(SRCS:.cpp=.o)
OBJS = src/tcp_server.o src/ini_file.o src/ipdr_log.o
OBJS_ALL = $(OBJS) src/main.o
TARGET = ipdr_log

.PHONY: all
all: $(TARGET) 

.PHONY: test
test: $(TARGET) test/test_main.o
	$(CPP) $(CPPFLAGS) -o test/test_all test/test_ipdr_log.cpp $(OBJS) \
		test/test_main.o $(LDFLAGS)

$(TARGET): $(OBJS_ALL) 
	$(CPP) $(CPPFLAGS) -o $(TARGET) $(OBJS_ALL) $(LDFLAGS) 

.PHONY: clean
clean:
	rm -f $(TARGET) src/*.o test/*.o
