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

- `base_num`: an integer between 10 and 99

  - Make sure it's not being used by another cvd instance running at the same time (by you or another person)

- `kernel`: path to your kernel image

- `initramfs`: path to your initramfs file

- `ori_cf`: path to your GSI folder where you extracted the contents of the two compressed files

## Run the launcher

Execute `main.py` with `sudo` to ensure access to `/dev/net/tun` (CAP_NET_ADMIN required).

```sh
sudo venv/bin/python main.py
```

Press Ctrl+C to stop it.
