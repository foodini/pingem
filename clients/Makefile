CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++11
SDL_CFLAGS := $(shell sdl2-config --cflags)
SDL_LIBS   := $(shell sdl2-config --libs)

WARNINGS = -Wall -Wextra
IMGUI    = ../third_party/imgui

OUR_OBJECTS   = main.o daemon_link.o target_history.o timeline.o tabulation.o row_view.o \
                protocol.o
IMGUI_OBJECTS = imgui.o imgui_draw.o imgui_tables.o imgui_widgets.o \
                imgui_impl_sdl2.o imgui_impl_opengl3.o

pingem: $(OUR_OBJECTS) $(IMGUI_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(SDL_LIBS) -lGL -ldl

# Our code: full warnings.
%.o: %.cpp *.h ../shared/protocol.h
	$(CXX) $(CXXFLAGS) $(WARNINGS) $(SDL_CFLAGS) -I$(IMGUI) -c $<

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

.PHONY: clean
