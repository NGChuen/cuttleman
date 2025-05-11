```sh
cd cuttleman
python3 -m venv venv
source venv/bin/activate
pip install pexpect psutil
```

In the main function of `main.py`, change `base_num`, `kernel`, `initramfs` and `ori_cf`.

```sh
sudo venv/bin/python main.py
```
