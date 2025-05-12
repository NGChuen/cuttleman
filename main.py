import grp
import os
import pexpect
import psutil
import shlex
import shutil
import subprocess


assert os.access('/dev/kvm', os.R_OK | os.W_OK)
assert os.access('/dev/vhost-vsock', os.R_OK | os.W_OK)
in_cvdnetwork_group = False
for gid in os.getgroups():
    if grp.getgrgid(gid).gr_name == 'cvdnetwork':
        in_cvdnetwork_group = True
        break
assert in_cvdnetwork_group


PROJ_DIR = os.path.dirname(os.path.abspath(__file__))
CFS = os.path.join(PROJ_DIR, 'cfs')  # Temporary directory for storing data from different cvd instances


def create_symlinked_copy(src, dst):
    if os.path.exists(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)

    for name in os.listdir(src):
        src_path = os.path.join(src, name)
        dst_link = os.path.join(dst, name)
        os.symlink(src_path, dst_link)


class CVDInstance:
    def __init__(self, base_num: int):
        if base_num < 10 or base_num > 99:
            raise ValueError('Base number must be between 10 and 99 for QEMU compatibility')

        self.base_num: int = base_num
        self.cf: str = os.path.join(CFS, str(base_num))
        self.adb_port: int = 6520 + base_num - 1
        self.adb_path: str = os.path.join(self.cf, 'bin/adb')
        self.adb_shell_cmd: str = f'{self.adb_path} -s 0.0.0.0:{self.adb_port} shell'
        self.gdb_port: int = 1234 + base_num - 1
        self._run_cvd_path: str = os.path.join(self.cf, 'bin/run_cvd')

    def start(self, kernel: str, initramfs: str, ori_cf: str, use_qemu: bool = True, enable_gdb: bool = True) -> bool:
        """Start a cvd instance using launch_cvd script.

        Note:
            This method blocks on launch.expect. Could hang indefinitely
            without reporting whether boot was successful.

        Returns:
            True if the instance booted successfully, False otherwise.
        """
        # Stop the cvd instance you started earlier with the same base number, if any.
        self.force_stop()

        create_symlinked_copy(ori_cf, self.cf)

        logfile = open(os.path.join(self.cf, 'launch_cvd_output'), 'w')
        print(f'Running launch_cvd. You MUST keep an eye on {logfile.name}')

        env = os.environ.copy()
        env['HOME'] = self.cf
        args = [
            os.path.join(self.cf, 'bin/launch_cvd'),
            f'-kernel_path={kernel}',
            f'-initramfs_path={initramfs}',
            '--daemon',
            '-console=true',
            '-enable-audio=true',
            '-start_webrtc=true',
            '-tcp_port_range=15550:15599',
            '-udp_port_range=0:0',
            f'--base_instance_num={self.base_num}',
        ]
        if use_qemu:
            args.append('--vm_manager=qemu_cli')
            args.append(f'--qemu_binary_dir={PROJ_DIR}')
        if enable_gdb:
            args.extend([
                f'-gdb_port={self.gdb_port}',
                '-extra_kernel_cmdline=nokaslr'
            ])
            print('Connect to GDB, or the kernel won\'t start booting:')
            print(f'\ttarget remote :{self.gdb_port}')
        print('After the kernel boots, run:')
        print('\t' + self.adb_shell_cmd)
        cmd = shlex.join(args)
        launch = pexpect.spawn(cmd, cwd=self.cf, env=env, encoding='utf-8', logfile=logfile)
        launch.sendline()
        launch.expect(pexpect.EOF, timeout=None)
        if 'VIRTUAL_DEVICE_BOOT_COMPLETED' in launch.before:
            print('[+] Boot succeeded')
            return True
        elif 'VIRTUAL_DEVICE_BOOT_FAILED' in launch.before:
            print('[-] Boot failed (1)')
        else:
            print('[-] Boot failed (2)')
        self.force_stop()
        return False

    def stop(self):
        """Stop the cvd instance using stop_cvd script."""
        env = os.environ.copy()
        env['HOME'] = self.cf
        subprocess.run([os.path.join(self.cf, 'bin/stop_cvd')], cwd=self.cf, env=env)

    def force_stop(self):
        """Forcefully stop the cvd instance, if it is running."""
        killed = False
        for proc in psutil.process_iter(['pid', 'exe', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and cmdline[0] == self._run_cvd_path:
                    proc.kill()
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if killed:
            print('[+] Killed')

    def get_adb_shell(self):
        """Open an interactive ADB shell session to the cvd instance."""
        print('Ctrl+D to exit the shell')
        adb = pexpect.spawn(
            self.adb_shell_cmd,
            echo=True,
            cwd=self.cf,
            encoding='utf-8',
            codec_errors='ignore',
        )
        adb.interact()


if __name__ == '__main__':
    base_num = 30  # TODO: change me
    kernel = '/home/zlian064/android/Image'  # TODO: change me
    initramfs = '/home/zlian064/android/initramfs.img'  # TODO: change me
    ori_cf = '/home/zlian064/cf'  # TODO: change me

    cvd = CVDInstance(base_num)
    try:
        cvd.start(kernel, initramfs, ori_cf)
    except KeyboardInterrupt:
        cvd.force_stop()
