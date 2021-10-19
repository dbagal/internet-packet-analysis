import logging
import datetime
import os

ROOT_FOLDER = ""

def get_bits(bytes, byteorder="big"):
        bits = []
        if byteorder=="big":
            bit_indices = range(7,-1,-1)
        elif byteorder=="little":
            bit_indices = range(0,8)

        for byte in bytes:
            bits += [(byte>>i)&1 for i in bit_indices]

        return bits

def log(fname, msg):
    fname = os.path.join(ROOT_FOLDER, f"logs/{fname}.log")
    logging.basicConfig(filename=fname, level=logging.INFO)
    current_ts = datetime.datetime.now().strftime("%m-%d-%Y::%H:%M:%S")
    msg = current_ts+"::"+msg
    logging.info(msg+"\n")
    print("\n",msg,"\n")


def get_string_representation(contents):
    max_len = 70
    processed_contents = []
    for content in contents:
        if len(content)>max_len:
            chunks = [content[i:i+max_len] for i in range(0, len(content), max_len)]
            processed_contents.extend(chunks)
        else:
            processed_contents += [content]

    border_len = len(max(processed_contents, key=lambda x: len(x)))
    bordered_contents = ["| " + txt.ljust(border_len) + " |" for txt in processed_contents]
    border_len = len(max(contents, key=lambda x: len(x)))
    bordered_contents = ["| " + txt.ljust(border_len) + " |" for txt in contents]
    string_rep = "\n" + "="*(border_len+4)+ "\n" + "\n".join(bordered_contents) + "\n"+ "="*(border_len+4) + "\n"
    return string_rep




