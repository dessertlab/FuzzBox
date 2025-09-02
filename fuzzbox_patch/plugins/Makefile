CC=gcc
LDFLAGS=--shared
CFLAGS=-fPIC -I/usr/include/glib-2.0 -I/usr/lib/i386-linux-gnu/glib-2.0/include -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

customplugin: plugin_mils.c
	$(CC) -o customplugin.so $(LDFLAGS) plugin_mils.c $(CFLAGS)
linux: plugin_linux_32.c plugin_client_32.c cJSON.c cJSON.h json_utils.c json_utils.h
	$(CC) -o customplugin.so $(LDFLAGS) plugin_linux_32.c cJSON.c json_utils.c $(CFLAGS)
#	$(CC) -o clientplugin.so $(LDFLAGS) plugin_client_32.c cJSON.c json_utils.c $(CFLAGS) -lcurl -lpthread

clean:
	rm -f *.so
