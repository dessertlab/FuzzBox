import subprocess
import time
import pyautogui as pag

DELAY = 0.1
INTER_INSTR_DELAY = 6

def simulate_keyboard_input(text):
    # Delay to give some time before starting the input
    # Simulate key presses
    pag.write(text, interval=DELAY)
    time.sleep(0.1)
    pag.press('enter')

def change_keyboard_layout(layout_name):
    try:
        subprocess.run(['setxkbmap', layout_name])
        print(f"Keyboard layout changed to {layout_name}")
    except Exception as e:
        print(f"Error changing keyboard layout: {e}")

if __name__ == "__main__":
    commands = [
        "root",
        "root",
        "ifconfig eth0 192.168.2.2/24",
        "echo 0 > /proc/sys/kernel/randomize_va_space",
        "mount -o bind /dev ./squashfs-root/dev",
        "mount -t proc /proc ./squashfs-root/proc",
        "mount -o bind /sys ./squashfs-root/sys",
        "chroot squashfs-root/ sh",
        "/etc/init.d/rcS; sleep 120; ifconfig br0 down; brctl delbr br0"
        #"chmod +x tools/patch.sh && /bin/sh tools/patch.sh",
        #"brctl addbr br0 && ifconfig br0 192.168.2.2/24 up",
        #"/bin/httpd"  # 1>/dev/null 2>&1 &",
        #"sleep 1 && chmod +x tools/getlibc.sh && /bin/sh tools/getlibc.sh"
    ]
    time.sleep(5)
    #change_keyboard_layout('us')
    for command in commands:
        time.sleep(INTER_INSTR_DELAY)
        simulate_keyboard_input(command)
    #change_keyboard_layout('it')
