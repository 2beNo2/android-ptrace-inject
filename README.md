# Android-Inject
### `ptrace-inject:` 
  - use ptrace-api inject arm/arm64 process
  #### how to build:
  - make sure have `ndk-build` in your PATH
  - type ndk-build at the command line
  - output at /libs
  #### how to use:
  ```
  -rwxrwxrwx 1 shell shell    14312 2022-12-02 16:14 inject
  -rwxrwxrwx 1 root  root    987604 2022-12-01 17:08 libc.so
  -rwxrwxrwx 1 shell shell     5976 2022-12-02 16:14 libtest.so
  blueline:/data/local/tmp # ./inject pid /data/local/tmp/libtest.so
  ```

