mkdir build/
g++ client_test.cpp ../client.cpp -o build/client
g++ server_test.cpp ../server.cpp ../../hook/HookPatch.cpp -o build/client
