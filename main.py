from enum import Enum
from argparse import ArgumentParser
from capstone import (
        Cs, 
        CS_ARCH_X86, 
        CS_MODE_64, 
        CS_MODE_32
)

class __architectures(Enum):
        X86_64 = CS_MODE_64
        X86_32 = CS_MODE_32

def __read_file_chunk(__path: str, __chunk_size: int) -> bytes:
        with open(__path, 'rb') as file:
                while True:
                        __currChunk = file.read(__chunk_size)
                        if not __currChunk:
                            break
                        yield __currChunk

def __disasm_file_(__path: str, __output: str, __architecture_mode_: __architectures) -> None:
        __chunk_size = 4096
        __batch = 1000
        cs = Cs(CS_ARCH_X86, __architecture_mode_.value)
        __instructions = []

        with open(__output, 'w') as __output_file:
                    for __currChunk in __read_file_chunk(__path, __chunk_size):
                            for __instruc in cs.disasm(__currChunk, 0x1000):
                                    __instructions.append(f"[MNEMONIC] {__instruc.mnemonic:8}\t[OP] {__instruc.op_str:20}\t\t@ ->\t\t[MEM_ADDR] 0x{__instruc.address:08x}\n")
                            if len(__instructions) >= __batch:
                                 __output_file.writelines(__instructions)
                                 __instructions.clear()
                            __output_file.writelines(__instructions)

def __arg_parser() -> None:
        parser = ArgumentParser()

        parser.add_argument("-f", "--file-path", help="file path")
        parser.add_argument("-o", "--output-path", help="output path")
        parser.add_argument(
                "-m",
                "--mode",
                type=__architectures,
                choices=list(__architectures),
                default=__architectures.X86_64,
                help="select mode",
    )

        return parser.parse_args()

def main() -> None:
        args = __arg_parser()
        __disasm_file_(args.file_path, args.output_path, args.mode)

if __name__ == "__main__":
            main()