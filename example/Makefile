CXX := g++
CXXFLAGS += -std=c++17 -Wall -Wextra -g
CPPFLAGS += -I..
LDFLAGS +=
LDLIBS += -pthread

ASAN ?= 0
ifeq ($(ASAN), 1)
  CXXFLAGS += -fsanitize=address -fsanitize=leak
endif

socket: LDLIBS += -lcrypto -lssl
sqlite: LDLIBS += -lsqlite3

%: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -MMD -MP -MF .$(@).d -o $@ $< $(LDFLAGS) $(LDLIBS)
	@cat .*.d | awk -F: 'BEGIN { print ".gitignore"; print "*.pem" }; /^[a-z]/ { print $$1; print "." $$1 ".d" }' > .gitignore

.PHONY: leak-check

leak-check:
	@if [ -z "$(filter-out test, $(MAKECMDGOALS))" ]; then \
		exit 1; \
	fi; \
	for target in $(filter-out leak-check, $(MAKECMDGOALS)); do \
		valgrind --leak-check=full -s --track-fds=yes ./$$target; \
	done

-include .*.d
