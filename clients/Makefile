CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++11
SDL_CFLAGS := $(shell sdl2-config --cflags)
SDL_LIBS   := $(shell sdl2-config --libs)

WARNINGS = -Wall -Wextra
IMGUI    = ../third_party/imgui

OUR_OBJECTS   = main.o daemon_link.o target_history.o timeline.o tabulation.o row_view.o \
                route_store.o route_graph.o route_view.o reverse_dns.o public_suffix.o \
                protocol.o
IMGUI_OBJECTS = imgui.o imgui_draw.o imgui_tables.o imgui_widgets.o \
                imgui_impl_sdl2.o imgui_impl_opengl3.o

# The Public Suffix List, for naming the owners of routers (see
# public_suffix.h). Fetched once, the first time you build; `make update-psl`
# fetches a fresh copy. pingem never downloads anything itself. If the fetch
# fails, the build carries on and pingem falls back to a simple guess.
PSL_DIR  = $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/pingem
PSL_FILE = $(PSL_DIR)/public_suffix_list.dat
PSL_URL  = https://publicsuffix.org/list/public_suffix_list.dat

all: pingem $(PSL_FILE)

pingem: $(OUR_OBJECTS) $(IMGUI_OBJECTS)
	$(CXX) $(CXXFLAGS) -pthread -o $@ $^ $(LDFLAGS) $(SDL_LIBS) -lGL -ldl

# Fetches the list, or explains why not. $(1) is the exit status on failure:
# 0 when it's just the automatic first-build fetch, 1 for "make update-psl".
define fetch_psl
	@mkdir -p $(PSL_DIR)
	@echo "fetching the Public Suffix List into $(PSL_DIR)"
	@curl -fsS --max-time 30 -o $(PSL_FILE).tmp $(PSL_URL) && mv $(PSL_FILE).tmp $(PSL_FILE) || \
	  { rm -f $(PSL_FILE).tmp; \
	    echo "  (couldn't fetch it; pingem will guess router owners without it)"; exit $(1); }
endef

$(PSL_FILE):
	$(call fetch_psl,0)

update-psl:
	$(call fetch_psl,1)

# Our code: full warnings.
%.o: %.cpp *.h ../shared/protocol.h
	$(CXX) $(CXXFLAGS) $(WARNINGS) -pthread $(SDL_CFLAGS) -I$(IMGUI) -c $<

protocol.o: ../shared/protocol.cpp ../shared/protocol.h
	$(CXX) $(CXXFLAGS) $(WARNINGS) -c $<

# Vendored ImGui: built as-is, without our warning flags.
imgui.o: $(IMGUI)/imgui.cpp
	$(CXX) $(CXXFLAGS) -c $<

imgui_%.o: $(IMGUI)/imgui_%.cpp
	$(CXX) $(CXXFLAGS) -c $<

imgui_impl_%.o: $(IMGUI)/backends/imgui_impl_%.cpp
	$(CXX) $(CXXFLAGS) $(SDL_CFLAGS) -I$(IMGUI) -c $<

clean:
	rm -f pingem $(OUR_OBJECTS) $(IMGUI_OBJECTS)

.PHONY: all clean update-psl
