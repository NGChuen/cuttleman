# Cuttleman

## Set up the Python environment

```sh
cd cuttleman
python3 -m venv venv
source venv/bin/activate
pip install pexpect psutil
```

## Configure paths

Open main.py and update the following variables in the `__main__` section:

`base_num`: a unique integer between 10 and 99

`kernel`: path to your kernel image (e.g., Image)

`initramfs`: path to your initramfs file

`ori_cf`: directory where you extracted the contents of the two compressed files.

## Run the launcher

Execute `main.py` with `sudo` to ensure access to `/dev/net/tun` (CAP_NET_ADMIN required).

```sh
sudo venv/bin/python main.py
```

Press Ctrl+C to exit.
