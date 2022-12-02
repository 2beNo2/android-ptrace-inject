

all:
	adb push ./libs/armeabi-v7a/inject /data/local/tmp/inject
	adb push ./libs/armeabi-v7a/libtest.so /data/local/tmp/
	adb shell chmod 777 /data/local/tmp/inject
	adb shell chmod 777 /data/local/tmp/libtest.so
	adb shell /data/local/tmp/inject

arm64:
	adb push ./libs/arm64-v8a/inject /data/local/tmp/inject
	adb push ./libs/arm64-v8a/libtest.so /data/local/tmp/
	adb shell chmod 777 /data/local/tmp/inject
	adb shell chmod 777 /data/local/tmp/libtest.so
	adb shell /data/local/tmp/inject

clean:
	rm -rf obj
	rm -rf libs
