from disasm import (
        __architectures,
        __disasm_file_
)

from argparse import ArgumentParser

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
        parser.add_argument(
               "-of",
               "--output-format",
               choices=["txt", "json"],
               default="txt",
               help="output format",
    )

        return parser.parse_args()

def main() -> None:
        args = __arg_parser()
        __disasm_file_(args.file_path, args.output_path, args.mode, args.output_format)

if __name__ == "__main__":
            main()
