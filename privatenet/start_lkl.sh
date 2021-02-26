docker build .
sgx-lkl-disk create --size=500M --docker=./Dockerfile sgxlkl-disk.img
SGXLKL_TAP=sgxlkl_tap0 sgx-lkl-run-oe --sw-debug ./sgxlkl-disk.img /usr/local/bin/python3 /app/voting.py
