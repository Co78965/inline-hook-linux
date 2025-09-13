mkdir build/
g++ -std=c++17 -fPIC -shared -o build/libempty.so so.cpp ../hook/HookPatch.cpp ../pipe/server.cpp -lZydis -ldl -lpthread