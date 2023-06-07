from enum import Enum
from typing import Optional
from json import dump
from os.path import exists
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
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

def __symbol_resolution_(_symbols: Optional[SymbolTableSection], address: int) -> str:
        if _symbols:
                for symbol in _symbols.iter_symbols():
                        if symbol['st_value'] == address:
                                return symbol.name
        return ""

def __disasm_file_(__path: str, __output: str, __architecture_mode_: __architectures, output_format: str) -> None:
        __chunk_size = 4096
        __batch = 1000
        cs = Cs(CS_ARCH_X86, __architecture_mode_.value)
        __instructions = []

        _symbols = ELFFile(open(__path, 'rb')).get_section_by_name('.symtab') if exists(__path) else None

        for curr_chunk in __read_file_chunk(__path, __chunk_size):
            for instruc in cs.disasm(curr_chunk, 0x1000):
                symbol_name = ""
                if _symbols:
                    symbol_name = __symbol_resolution_(_symbols, instruc.address)
                    __instructions.append({
                    'mnemonic': instruc.mnemonic,
                    'op_str': instruc.op_str,
                    'address': instruc.address,
                    'symbol': symbol_name
            })

        write_instructions(__output, __path, __chunk_size, __instructions, cs, __batch, output_format, _symbols)

def write_instructions(output, path, chunk_size, instructions, cs, batch, output_format, _symbols):
        with open(output, 'w') as output_file:
                if output_format == 'json':
                        dump(instructions, output_file, indent=6)
                else:
                        for __currChunk in __read_file_chunk(path, chunk_size):
                                for instruc in cs.disasm(__currChunk, 0x1000):
                                        instructions.append(
                                        {
                                                'mnemonic': instruc.mnemonic,
                                                'op_str': instruc.op_str,
                                                'address': instruc.address,
                                                'symbol': __symbol_resolution_(_symbols, instruc.address) if _symbols else ''
                                        }
                                        )
                        if len(instructions) >= batch:
                                        output_file.writelines(
                                                        [
                                f"[MNEMONIC] {instr['mnemonic']:8}\t[OP] {instr['op_str']:20}\t\t@ ->\t\t[MEM_ADDR] 0x{instr['address']:08x}\n"
                                for instr in instructions
                            ]
                        )
                                        instructions.clear()
                output_file.writelines(
                        [
                                f"[MNEMONIC] {instr['mnemonic']:8}\t[OP] {instr['op_str']:20}\t\t@ ->\t\t[MEM_ADDR] 0x{instr['address']:08x}\n"
                                for instr in instructions
                         ]
            )
