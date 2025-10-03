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
CFS = os.path.join(PROJ_DIR, 'cfs')  # Temporary directory for storing GSI folders from different cvd instances


def create_symlinked_copy(src, dst):
    os.makedirs(dst)

    for name in os.listdir(src):
        src_path = os.path.join(src, name)
        dst_link = os.path.join(dst, name)
        os.symlink(src_path, dst_link)


def force_stop_cvd_instances_launched_from_proj_dir(filter_fn = lambda cmdline: cmdline[0].startswith(CFS)):
    killed = False
    denied = False
    for proc in psutil.process_iter(['pid', 'exe', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline and filter_fn(cmdline):
                proc.kill()
                killed = True
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            denied = True
            continue

    if denied:
        print('[-] Please use sudo to stop the previous CVD instance(s).')
        return False
    if killed:
        print('[+] Killed')
    return True


class CVDInstance:
    def __init__(self, base_num: int):
        self.base_num: int = base_num
        self.cf: str = os.path.join(CFS, str(base_num))
        self.launch_cvd_output_path = os.path.join(self.cf, 'launch_cvd_output')
        self.launcher_log_path = os.path.join(self.cf, f'cuttlefish_runtime/launcher.log')
        self.kernel_log_path = os.path.join(self.cf, f'cuttlefish_runtime/kernel.log')
        self.adb_port: int = 6520 + base_num - 1
        self.adb_path: str = os.path.join(self.cf, 'bin/adb')
        self.adb_cmd_base_args: str = [self.adb_path, '-s', f'0.0.0.0:{self.adb_port}']
        self.console: str = os.path.join(self.cf, f'cuttlefish_runtime/console')
        self.gdb_port: int = 1234 + base_num - 1

    def start(
        self,
        kernel: str,
        initramfs: str,
        ori_cf: str,
        use_crosvm: bool = True,
        crosvm_binary: str = None,
        qemu_binary_dir: str = None,
        cpus: int = 2,
        memory_mb: int = 2048,
        extra_kernel_cmdline_split: list[str] = None,
        enable_kgdb: bool = False,
        enable_vm_gdb: bool = False,
    ) -> bool:
        """Start a cvd instance using launch_cvd script.

        Args:
            kernel (str): Path to the kernel image.
            initramfs (str): Path to the initramfs image.
            ori_cf (str): Path to the GSI folder.
            use_crosvm (bool, optional): Whether to use crosvm (True) or QEMU (False).
            crosvm_binary (str, optional): Path to the crosvm binary.
                Optional if use_crosvm is True.
                Ignored if use_crosvm is False.
            qemu_binary_dir (str, optional): Directory containing QEMU binaries.
                Optional if use_crosvm is False.
                Ignored if use_crosvm is True.
            cpus (int, optional): Number of CPUs.
            memory_mb (int, optional): Amount of memory (in megabytes).
            extra_kernel_cmdline_split (list[str], optional): List of additional kernel command-line parameters.
            enable_kgdb (bool, optional): Whether to enable KGDB.
            enable_vm_gdb (bool, optional): Whether to enable VM-level GDB.

        Returns:
            True if the instance booted successfully, False otherwise.

        Note:
            This method blocks on launch.expect. Could hang indefinitely
            without reporting whether boot was successful.
        """
        if not use_crosvm and (self.base_num < 10 or self.base_num > 99):
            print('[-] Base number must be between 10 and 99 for QEMU compatibility')
            return False

        # Stop the previous cvd instance you started with the same base number, if any.
        if not self.force_stop():
            return False

        # Delete the GSI folder of the previous cvd instance.
        if os.path.exists(self.cf):
            try:
                shutil.rmtree(self.cf)
            except PermissionError:
                print(f'[-] Please use sudo to delete {self.cf}')
                return False

        # Create a GSI folder for the current cvd instance.
        create_symlinked_copy(ori_cf, self.cf)

        logfile = open(self.launch_cvd_output_path, 'w')
        print(f'Running launch_cvd. MUST keep an eye on:')
        print(f'\tits output:\t{self.launch_cvd_output_path}')
        print(f'\tlauncher log:\t{self.launcher_log_path}')
        print(f'\tkernel log:\t{self.kernel_log_path}')

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
        if use_crosvm:
            if crosvm_binary:
                args.append(f'--crosvm_binary={crosvm_binary}')
        else:
            args.append('--vm_manager=qemu_cli')
            if qemu_binary_dir:
                args.append(f'--qemu_binary_dir={qemu_binary_dir}')
        if enable_kgdb:
            args.append('--kgdb')
        if enable_vm_gdb:
            if use_crosvm:
                cpus = 1
            args.append(f'-gdb_port={self.gdb_port}')
            print('Connect to GDB, or the kernel won\'t start booting:')
            print(f'\ttarget remote :{self.gdb_port}')
        if extra_kernel_cmdline_split is None:
            extra_kernel_cmdline_split = []
        else:
            extra_kernel_cmdline_split = extra_kernel_cmdline_split[:]
        if enable_kgdb or enable_vm_gdb:
            extra_kernel_cmdline_split.append('nokaslr')
        args.extend([
            f'-cpus={cpus}',
            f'-memory_mb={memory_mb}',
            '-extra_kernel_cmdline="' + ' '.join(extra_kernel_cmdline_split) + '"'
        ])
        print('After the kernel boots, run:')
        print('\t' + shlex.join(self.adb_cmd_base_args + ['shell']))
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

    def force_stop(self) -> bool:
        """Forcefully stop the cvd instance, if it is running."""
        return force_stop_cvd_instances_launched_from_proj_dir(lambda cmdline: cmdline[0].startswith(self.cf))

    def run_adb_subcommand(self, subcmd_args: list[str], timeout: float = None) -> bytes:
        p = subprocess.run(
            self.adb_cmd_base_args + subcmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.stdout

    def get_adb_shell(self):
        """Open an interactive ADB shell session to the cvd instance."""
        print('Ctrl+D to exit the shell')
        adb = pexpect.spawn(
            shlex.join(self.adb_cmd_base_args + ['shell']),
            echo=True,
            cwd=self.cf,
            encoding='utf-8',
            codec_errors='ignore',
        )
        adb.interact()

    def run_command_in_adb_shell(self, cmd: str, timeout: float = None) -> tuple[bool, bytes]:
        stdout = self.run_adb_subcommand(['shell', cmd], timeout)
        return b'adb: error:' not in stdout, stdout

    def adb_push(self, srcs: list[str], dst: str) -> bool:
        stdout = self.run_adb_subcommand(['push'] + srcs + [dst])
        return b'adb: error:' not in stdout

    def adb_pull(self, src: str, dst: str) -> bool:
        stdout = self.run_adb_subcommand(['pull', src, dst])
        return b'adb: error:' not in stdout


if __name__ == '__main__':
    base_num = 30  # TODO: change me
    kernel = '/home/zlian064/android/Image'  # TODO: change me
    initramfs = '/home/zlian064/android/initramfs.img'  # TODO: change me
    ori_cf = '/home/zlian064/cf'  # TODO: change me

    cvd = CVDInstance(base_num)
    try:
        cvd.start(
            kernel,
            initramfs,
            ori_cf,
            use_crosvm=True,
            crosvm_binary=None,
            qemu_binary_dir=None,  # Use PROJ_DIR when booting an arm64 kernel on QEMU
            cpus=2,
            memory_mb=4096,
            extra_kernel_cmdline_split=['stack_depot_disable=off'],
            enable_kgdb=False,
            enable_vm_gdb=False,
        )
    except KeyboardInterrupt:
        cvd.force_stop()
