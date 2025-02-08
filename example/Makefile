CXX := g++
CXXFLAGS += -std=c++17 -Wall -Wextra -g
CPPFLAGS += -I..
LDFLAGS +=
LDLIBS += -pthread

sqlite: LDLIBS += -lsqlite3

%: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -MF .$(@).d -o $@ $< $(LDFLAGS) $(LDLIBS)
	@cat .*.d | awk -F: 'BEGIN { print ".gitignore" }; /^[a-z]/ { print $$1; print "." $$1 ".d" }' > .gitignore

-include .*.d
