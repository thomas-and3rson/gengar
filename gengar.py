"""
author: thomas anderson

Shellcode obfuscator that generates equivalent shellcode using different instructions
And also add a prologue to the shellcode that exauhst the code simulation

"""
import argparse
import logging
from typing import Optional
import colorama
import random
import sys
from capstone import *
from keystone import *

X86 = "x86"
X64 = "x64"
EXTENDED_X64 = "x64-extended"

colorama.init()


class ColorFormatter(logging.Formatter):
    # Change this dictionary to suit your coloring needs!
    COLORS = {
        "WARNING": colorama.Fore.RED,
        "ERROR": colorama.Fore.RED + colorama.Back.WHITE,
        "DEBUG": colorama.Fore.BLUE,
        "INFO": colorama.Fore.GREEN,
        "CRITICAL": colorama.Fore.RED + colorama.Back.WHITE
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        if color:
            record.name = color + record.name
            record.levelname = color + record.levelname
            record.msg = color + record.msg
        return logging.Formatter.format(self, record)


class ColorLogger(logging.Logger):
    def __init__(self, name):
        logging.Logger.__init__(self, name, logging.DEBUG)
        color_formatter = ColorFormatter("%(name)s [*] %(message)s")
        console = logging.StreamHandler()
        console.setFormatter(color_formatter)
        self.addHandler(console)


logging.setLoggerClass(ColorLogger)
logger = logging.getLogger("$")

ALLLOWED_REGS = {
    X86: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"],
    X64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"],
    EXTENDED_X64: ["r8", "r9", "r10", "r11" "r13", "r14", "r15"]
}


def sh_equivalents_x64() -> list:
    return [
        (["xor $r1, $r1", "sub $r1, $r1"], (X64, X86, EXTENDED_X64)),
        (["xor $r1, $r1;NOP;NOP;NOP;NOP", "mov $r1, 0",
         "sub $r1, $r1;NOP;NOP;NOP;NOP"], (X64, X86, EXTENDED_X64)),
        (["add $r1, 1", "inc $r1;NOP"], (X64, X86, EXTENDED_X64)),

        (["sub $r1, 1", "dec $r1;NOP"], (X64, X86, EXTENDED_X64)),
        (["jmp $r1", "push $r1;ret"], (X64, X86, EXTENDED_X64)),
        (["push $1; pop $r2; NOP", "mov $r2, $1"], (X64, X86)),
        (["push $1; pop $r2", "mov $r2, $1;NOP"], (EXTENDED_X64,)),

    ]


def sh_equivalents(arch) -> Optional[list]:
    # TO DO - implement the shellcode equivalents for x86
    # if arch == X86:
    # sh_equivalents_x86()
    if arch == X64:
        return sh_equivalents_x64()
    else:
        logger.error("Invalid architecture")

    return None


def check_patterns(ks, r1, r2, mnemonic, instr, list_shellcode_alternatives):
    patched_shellcode = []
    has_changed = False
    count_changes = 0

    for patterns, allows in list_shellcode_alternatives:
        for index, pattern in enumerate(patterns):
            list_allows = []
            [list_allows.extend(ALLLOWED_REGS[allow]) for allow in allows]
            # replace registers
            if pattern.find("$r1") != -1 and r1:
                if r1 not in list_allows:
                    continue
                pattern = pattern.replace("$r1", r1)
                if pattern.find("$r2") != -1 and r2:
                    if r2 not in list_allows:
                        continue
                    pattern = pattern.replace("$r2", r2)

                if pattern.find("$r1") != -1 or pattern.find("$r2") != -1:
                    continue

                try:
                    get_asm = ks.asm(pattern)
                except KsError:
                    patched_shellcode.append(instr.bytes)
                    continue
                bsarray = bytearray(get_asm[0])

                if bsarray == instr.bytes:

                    random_index = index
                    while random_index == index:
                        random_index = random.randint(0, len(patterns) - 1)
                    data = patterns[random_index]
                    # replace $r1 and $r2
                    if data.find("$r1") != -1 and r1:
                        data = data.replace("$r1", r1)
                    if data.find("$r2") != -1 and r2:
                        data = data.replace("$r2", r2)

                    ks_asm = ks.asm(data)
                    patched_shellcode.append(ks_asm[0])

                    logger.warning(f"{mnemonic} {r1} {r2} -> {data}")
                    has_changed = True
                    count_changes += 1

    return patched_shellcode, has_changed, count_changes


def junk_code():

    junk = ["push rax; pop rax", "push rcx; pop rcx", "push rdx; pop rdx"]
    # choise a random junk
    random_junk = random.choice(junk)
    return random_junk


def create_prologue(ks, arch):

    random_offset = random.randint(0x4, 0x7f)
    random_offset_str = hex(random_offset)

    random_cmp = random.randint(0x4, 0x9)
    random_cmp_str = hex(random_cmp)

    possible_order = [0, 1, 2]
    random.shuffle(possible_order)
    push_acess_list = ["push rax", "push rcx", "push rdx"]
    pop_acess_list = ["pop rax", "pop rcx", "pop rdx"]

    # sort the registers
    new_push_acess_list = [push_acess_list[i] for i in possible_order]
    new_pop_acess_list = [pop_acess_list[i] for i in possible_order][::-1]

    prologue = f"""{";".join(new_push_acess_list)};
                movabs rax, 0x68732f6e69622f;
                {junk_code()};
                lea rcx, [rsp + {random_offset_str}];
                cdq
                idiv rcx
                mov rdx, rax
                {junk_code()};
            entrypoint:
                test rdx, 1
                jnz end;
                mov rax, rdx
                mov rcx, {random_cmp_str}
                cdq
                idiv rcx
                test rdx, rdx
                {junk_code()};
                add rdx, 0x1
                dec rdx
                jmp entrypoint
                {junk_code()};
            end:
                {";".join(new_pop_acess_list)};

            """
    asm_prologue = ks.asm(prologue)
    return asm_prologue[0]


def apply_obfuscation(ks, disassembled, arch) -> bytes:

    patched_shellcode = []
    # TODO make polymorphic prologue
    asm_prologue = create_prologue(ks, arch)
    patched_shellcode.append(asm_prologue)
    count_changes = 0
    for i in disassembled:
        instr, mnemonic, operands = i
        # check if match with pattern_eqs

        if len(operands) == 0:
            patched_shellcode.append(instr.bytes)
            continue
        r1, r2 = (operands + [None])[:2]
        list_shellcode_alternatives = sh_equivalents(arch)
        if not list_shellcode_alternatives:
            break
        composer_shellcode, change, inner_changes = check_patterns(
            ks, r1, r2, mnemonic, instr, list_shellcode_alternatives)
        composer_shellcode_rev, change_rev, inner_changes_rev = check_patterns(
            ks, r2, r1, mnemonic, instr, list_shellcode_alternatives)

        count_changes += inner_changes + inner_changes_rev
        if change:
            patched_shellcode.extend(composer_shellcode)
        elif change_rev:
            patched_shellcode.extend(composer_shellcode_rev)
        else:
            patched_shellcode.append(instr.bytes)

    if count_changes > 0:
        logger.info(
            f"{count_changes}/{len(disassembled)} instructions updated")
    else:
        logger.info(f"No instructions updated")

    return b"".join(bytes(i) for i in patched_shellcode)


def main():

    print()
    # usage: gengar.py -s <shellcode> -a <arch>
    parser = argparse.ArgumentParser(
        description='Generate obfuscated shellcode')
    parser.add_argument('-s', '--shellcode',
                        help='Shellcode to obfuscate', required=True)
    parser.add_argument(
        '-a', '--arch', help='Architecture of the shellcode', required=True)
    args = parser.parse_args()

    if args.arch == X86:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    elif args.arch == X64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    else:
        logger.error("Invalid architecture")
        sys.exit(1)
    md.detail = True
    md.skipdata = True

    if args.shellcode.startswith("\\x"):
        shellcode = args.shellcode.split("\\x")[1:]
        shellcode = bytes.fromhex("".join(shellcode))
    else:
        try:
            with open(args.shellcode, 'rb') as f:
                shellcode = f.read()
        except FileNotFoundError:
            logger.error("File not found")
            sys.exit(1)

    disassembled = []

    for i in md.disasm(shellcode, 0x0):
        operands = i.op_str.split(", ")
        disassembled.append((i, i.mnemonic, operands))
    patched_shellcode = apply_obfuscation(ks, disassembled, args.arch)
    print()
    logger.info(f"Original shellcode size: {len(shellcode)} bytes")
    logger.info(f"Obfuscated shellcode size: {len(patched_shellcode)} bytes")

    if len(shellcode) != len(patched_shellcode):
        logger.critical(f"Obfuscated shellcode size is different from original shellcode size \
            {colorama.Style.RESET_ALL}")
        # sys.exit(1)
    # reset color
    print()
    print("".join("\\x%02x" % i for i in patched_shellcode))
    print()


if __name__ == "__main__":
    main()
